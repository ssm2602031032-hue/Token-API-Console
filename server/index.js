import http from 'node:http'
import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { dirname, extname, join, normalize, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dataDir = process.env.DATA_DIR ? resolve(process.env.DATA_DIR) : join(root, 'data')
const dataFile = join(dataDir, 'store.json')
const distDir = join(root, 'dist')
const port = Number(process.env.PORT || process.argv[2] || 4174)
const adminToken = process.env.ADMIN_TOKEN || randomBytes(32).toString('hex')

const modelCatalog = [
  { id: 'claude-3-7-sonnet', name: 'Claude 3.7 Sonnet', provider: 'Anthropic', context: 200000, inputPrice: 3, outputPrice: 15, enabled: true },
  { id: 'gpt-4o', name: 'GPT-4o', provider: 'OpenAI', context: 128000, inputPrice: 2.5, outputPrice: 10, enabled: true },
  { id: 'gemini-2-5-pro', name: 'Gemini 2.5 Pro', provider: 'Google', context: 1000000, inputPrice: 1.25, outputPrice: 10, enabled: true },
  { id: 'deepseek-v3', name: 'DeepSeek V3', provider: 'DeepSeek', context: 128000, inputPrice: .27, outputPrice: 1.1, enabled: true }
]

const defaultStore = {users:[],keys:[],usage:{requests:0,inputTokens:0,outputTokens:0,cost:0},logs:[],settings:{workspaceName:'Demo',slug:'demo',usageAlerts:false},billing:{balance:0,plan:'demo',currency:'USD'},transactions:[]}

let store = await loadStore()
const sessions = new Map()

async function loadStore() {
  await mkdir(dataDir, { recursive: true })
  if (!existsSync(dataFile)) {
    await writeFile(dataFile, JSON.stringify(defaultStore, null, 2))
    return structuredClone(defaultStore)
  }
  try { return { ...structuredClone(defaultStore), ...JSON.parse(await readFile(dataFile, 'utf8')) } }
  catch { return structuredClone(defaultStore) }
}
async function saveStore() { await writeFile(dataFile, JSON.stringify(store, null, 2)) }
function json(res, status, body) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(body)) }
function apiError(res, status, message, type = 'invalid_request_error') { json(res, status, { error: { message, type, code: status } }) }
async function readJson(req) {
  const chunks = []; let size = 0
  for await (const chunk of req) { size += chunk.length; if (size > 1_000_000) throw new Error('请求体不能超过 1MB'); chunks.push(chunk) }
  if (!chunks.length) return {}
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { throw new Error('JSON 格式无效') }
}
function hashKey(value) { return createHash('sha256').update(value).digest('hex') }
function hashPassword(value, salt = randomBytes(16).toString('hex')) { return `${salt}:${scryptSync(value, salt, 64).toString('hex')}` }
function verifyPassword(value, stored) {
  const [salt, digest] = String(stored || '').split(':'); if (!salt || !digest) return false
  const candidate = scryptSync(value, salt, 64), expected = Buffer.from(digest, 'hex')
  return candidate.length === expected.length && timingSafeEqual(candidate, expected)
}
function publicUser(user) { return { id: user.id, name: user.name, email: user.email, createdAt: user.createdAt } }
function cookies(req) { return Object.fromEntries(String(req.headers.cookie || '').split(';').map(item => item.trim().split('=').map(decodeURIComponent)).filter(item => item.length === 2)) }
function sessionUser(req) { const session = sessions.get(cookies(req).tkapi_session); if (!session || session.expiresAt < Date.now()) return null; return store.users.find(user => user.id === session.userId) || null }
function createSession(res, user) { const token = randomBytes(32).toString('base64url'); sessions.set(token, { userId: user.id, expiresAt: Date.now() + 7 * 864e5 }); res.setHeader('Set-Cookie', `tkapi_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800`) }
function isAuthorized(req) {
  const raw = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.headers['x-admin-token'] || ''
  if (raw === adminToken) return true
  const digest = hashKey(raw)
  return store.keys.some(key => key.active && key.hash.length === digest.length && timingSafeEqual(Buffer.from(key.hash), Buffer.from(digest)))
}
function publicKey(key) { const { hash, ...safe } = key; return safe }
function estimateTokens(text) { return Math.max(1, Math.ceil(String(text || '').length / 3.2)) }
function recordLog(log) { store.logs.unshift(log); store.logs = store.logs.slice(0, 250); saveStore().catch(console.error) }

const server = http.createServer(async (req, res) => {
  const host=req.headers.host || ''; if(!/^(?:127\.0\.0\.1|localhost)(?::\d+)?$/.test(host))return apiError(res,403,'Local host only'); if(req.headers.origin && req.headers.origin !== 'http://'+host)return apiError(res,403,'Local origin only');
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/v1/')) {
    try { return await handleApi(req, res, url) } catch (error) { return apiError(res, 400, error.message) }
  }
  return serveStatic(res, url.pathname)
})

async function handleApi(req, res, url) {
  if (url.pathname === '/api/health' && req.method === 'GET') return json(res, 200, { status: 'ok', uptime: process.uptime(), version: '1.0.0' })
  if (url.pathname === '/api/auth/register' && req.method === 'POST') {
    const body = await readJson(req), email = String(body.email || '').trim().toLowerCase(), password = String(body.password || '')
    if (!/^\S+@\S+\.\S+$/.test(email)) return apiError(res, 422, '请输入有效邮箱')
    if (password.length < 8) return apiError(res, 422, '密码至少需要 8 位')
    if (store.users.some(user => user.email === email)) return apiError(res, 409, '该邮箱已注册')
    const user = { id: randomUUID(), name: String(body.name || email.split('@')[0]).trim().slice(0, 40), email, passwordHash: hashPassword(password), createdAt: new Date().toISOString() }
    store.users.push(user); await saveStore(); createSession(res, user); return json(res, 201, { user: publicUser(user) })
  }
  if (url.pathname === '/api/auth/login' && req.method === 'POST') {
    const body = await readJson(req), user = store.users.find(item => item.email === String(body.email || '').trim().toLowerCase())
    if (!user || !verifyPassword(String(body.password || ''), user.passwordHash)) return apiError(res, 401, '邮箱或密码错误', 'authentication_error')
    createSession(res, user); return json(res, 200, { user: publicUser(user) })
  }
  if (url.pathname === '/api/auth/me' && req.method === 'GET') { const user = sessionUser(req); return user ? json(res, 200, { user: publicUser(user) }) : apiError(res, 401, '请先登录', 'authentication_error') }
  if (url.pathname === '/api/auth/logout' && req.method === 'POST') { sessions.delete(cookies(req).tkapi_session); res.setHeader('Set-Cookie', 'tkapi_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); return json(res, 200, { loggedOut: true }) }
  if (url.pathname.startsWith('/api/') && !sessionUser(req)) return apiError(res, 401, '请先登录', 'authentication_error')
  if (url.pathname === '/api/dashboard' && req.method === 'GET') return json(res, 200, { usage: store.usage, logs: store.logs.slice(0, 20), models: modelCatalog, keys: store.keys.map(publicKey) })
  if (url.pathname === '/api/models' && req.method === 'GET') return json(res, 200, { data: modelCatalog })
  if (url.pathname === '/api/keys' && req.method === 'GET') return json(res, 200, { data: store.keys.map(publicKey) })
  if (url.pathname === '/api/keys' && req.method === 'POST') {
    const body = await readJson(req); if (!body.name?.trim()) return apiError(res, 422, '密钥名称不能为空')
    const secret = `tk_live_${randomBytes(24).toString('base64url')}`
    const key = { id: randomUUID(), name: body.name.trim().slice(0, 60), prefix: secret.slice(0, 15), suffix: secret.slice(-4), hash: hashKey(secret), createdAt: new Date().toISOString(), lastUsedAt: null, active: true }
    store.keys.unshift(key); await saveStore(); return json(res, 201, { ...publicKey(key), secret })
  }
  const keyMatch = url.pathname.match(/^\/api\/keys\/([^/]+)$/)
  if (keyMatch && req.method === 'DELETE') {
    const index = store.keys.findIndex(k => k.id === keyMatch[1]); if (index < 0) return apiError(res, 404, '密钥不存在')
    store.keys.splice(index, 1); await saveStore(); return json(res, 200, { deleted: true })
  }
  if (url.pathname === '/api/settings' && req.method === 'GET') return json(res, 200, store.settings)
  if (url.pathname === '/api/settings' && req.method === 'PUT') { store.settings = { ...store.settings, ...await readJson(req) }; await saveStore(); return json(res, 200, store.settings) }
  if (url.pathname === '/api/billing' && req.method === 'GET') return json(res, 200, { ...store.billing, transactions: store.transactions.slice(0, 50), plans: [{ id: 'starter', name: 'Starter', price: 0, requestLimit: 1000 }, { id: 'pro', name: 'Pro', price: 19, requestLimit: 100000 }, { id: 'team', name: 'Team', price: 59, requestLimit: 500000 }] })
  if (url.pathname === '/api/billing/topup' && req.method === 'POST') {
    const body = await readJson(req), amount = Number(body.amount)
    if (!Number.isFinite(amount) || amount < 5 || amount > 10000) return apiError(res, 422, '充值金额需要在 $5 到 $10,000 之间')
    const transaction = { id: `txn_${randomBytes(8).toString('hex')}`, type: 'topup', amount, status: 'succeeded', simulated: true, createdAt: new Date().toISOString() }
    store.billing.balance = Number((store.billing.balance + amount).toFixed(2)); store.transactions.unshift(transaction); await saveStore(); return json(res, 201, { balance: store.billing.balance, transaction })
  }
  if (url.pathname === '/api/billing/plan' && req.method === 'PUT') { const body = await readJson(req); if (!['starter','pro','team'].includes(body.plan)) return apiError(res, 422, '套餐不存在'); store.billing.plan = body.plan; await saveStore(); return json(res, 200, store.billing) }
  if (url.pathname === '/v1/models' && req.method === 'GET') {
    if (!isAuthorized(req)) return apiError(res, 401, 'API 密钥无效', 'authentication_error')
    return json(res, 200, { object: 'list', data: modelCatalog.filter(m => m.enabled).map(m => ({ id: m.id, object: 'model', created: 1767225600, owned_by: m.provider.toLowerCase() })) })
  }
  if (url.pathname === '/v1/chat/completions' && req.method === 'POST') {
    if (!isAuthorized(req)) return apiError(res, 401, 'API 密钥无效', 'authentication_error')
    const started = Date.now(), body = await readJson(req), model = modelCatalog.find(m => m.id === body.model)
    if (!model) return apiError(res, 404, '请求的模型不存在')
    if (store.billing.balance <= 0) return apiError(res, 402, '余额不足，请先充值', 'billing_error')
    if (!Array.isArray(body.messages) || !body.messages.length) return apiError(res, 422, 'messages 必须是非空数组')
    if (body.stream) return apiError(res, 400, '当前本地版本暂不支持 stream')
    const upstream = await callUpstream(body).catch(() => null)
    const answer = upstream?.choices?.[0]?.message?.content || createDemoAnswer(body.messages.at(-1)?.content)
    const inputTokens = upstream?.usage?.prompt_tokens || body.messages.reduce((n, m) => n + estimateTokens(m.content), 0)
    const outputTokens = upstream?.usage?.completion_tokens || estimateTokens(answer)
    const completion = upstream || { id: `chatcmpl_${randomBytes(8).toString('hex')}`, object: 'chat.completion', created: Math.floor(Date.now()/1000), model: body.model, choices: [{ index: 0, message: { role: 'assistant', content: answer }, finish_reason: 'stop' }], usage: { prompt_tokens: inputTokens, completion_tokens: outputTokens, total_tokens: inputTokens + outputTokens } }
    const requestCost = inputTokens/1e6*model.inputPrice + outputTokens/1e6*model.outputPrice
    store.usage.requests += 1; store.usage.inputTokens += inputTokens; store.usage.outputTokens += outputTokens; store.usage.cost = Number((store.usage.cost + requestCost).toFixed(4)); store.billing.balance = Number(Math.max(0, store.billing.balance - requestCost).toFixed(4))
    const rawToken = req.headers.authorization?.replace(/^Bearer\s+/i, ''); const key = store.keys.find(k => k.hash === hashKey(rawToken || '')); if (key) key.lastUsedAt = new Date().toISOString()
    recordLog({ id: completion.id, createdAt: new Date().toISOString(), route: '/v1/chat/completions', model: body.model, inputTokens, outputTokens, status: 200, latency: Date.now()-started })
    return json(res, 200, completion)
  }
  return apiError(res, 404, '接口不存在')
}

async function callUpstream(body) {
  if (!process.env.UPSTREAM_BASE_URL || !process.env.UPSTREAM_API_KEY) return null
  const response = await fetch(`${process.env.UPSTREAM_BASE_URL.replace(/\/$/, '')}/chat/completions`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.UPSTREAM_API_KEY}` }, body: JSON.stringify(body) })
  if (!response.ok) throw new Error(`上游返回 ${response.status}`)
  return response.json()
}
function createDemoAnswer(prompt) { return `已收到你的请求：“${String(prompt || '').slice(0, 120)}”。当前运行在本地演示模式，接口、鉴权、用量统计和日志记录均正常；配置 UPSTREAM_BASE_URL 与 UPSTREAM_API_KEY 后即可返回真实模型结果。` }
async function serveStatic(res, pathname) {
  const requested = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '')
  const file = normalize(join(distDir, requested))
  if (file !== distDir && !file.startsWith(distDir + (process.platform === 'win32' ? '\\' : '/'))) { res.writeHead(403); return res.end('Forbidden') }
  let target = file; if (!existsSync(target) || extname(target) === '') target = join(distDir, 'index.html')
  try { const data = await readFile(target); const types = { '.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png' }; res.writeHead(200, { 'Content-Type': types[extname(target)] || 'application/octet-stream' }); res.end(data) }
  catch { res.writeHead(404); res.end('Not found') }
}

server.listen(port, '127.0.0.1', () => console.log(`tkapi running at http://localhost:${port}`))
