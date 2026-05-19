import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 120000,
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status
    const detail = error.response?.data?.detail
    if (status === 429) {
      console.error('请求过于频繁，请稍后再试')
    } else if (status === 404) {
      console.error('资源不存在:', detail)
    } else if (status === 503) {
      console.error('服务暂时不可用:', detail)
    } else if (status >= 500) {
      console.error('服务器错误:', detail || error.message)
    }
    return Promise.reject(error)
  }
)

// ── 原有 API ──

export async function analyze(data) {
  const res = await api.post('/analyze', data)
  return res.data
}

export async function getHistory(limit = 50, offset = 0) {
  const res = await api.get('/history', { params: { limit, offset } })
  return res.data
}

export async function getHistoryDetail(id) {
  const res = await api.get(`/history/${id}`)
  return res.data
}

export async function getHistoryByTraceId(traceId) {
  const res = await api.get(`/history/trace/${traceId}`)
  return res.data
}

export async function getStats() {
  const res = await api.get('/stats')
  return res.data
}

export async function getScanStatsSummary() {
  const res = await api.get('/stats/scan')
  return res.data
}

export async function getReport(id, format = 'json') {
  const isText = format === 'markdown' || format === 'md' || format === 'html'
  const res = await api.get(`/report/${id}`, {
    params: { format },
    responseType: isText ? 'text' : 'json',
  })
  return res.data
}

export async function runEvaluation() {
  const res = await api.post('/evaluate')
  return res.data
}

// ── 新增 API: 靶标管理 ──

export async function getTargets() {
  const res = await api.get('/targets')
  return res.data
}

export async function getTargetDetail(targetId) {
  const res = await api.get(`/targets/${targetId}`)
  return res.data
}

export async function createTarget(data) {
  const res = await api.post('/targets', data)
  return res.data
}

export async function updateTarget(targetId, data) {
  const res = await api.put(`/targets/${targetId}`, data)
  return res.data
}

export async function deleteTarget(targetId) {
  const res = await api.delete(`/targets/${targetId}`)
  return res.data
}

export async function startTargetScan(targetId, config = {}) {
  const timeout = config.dataset ? 3600000 : 120000
  const res = await api.post(`/targets/${targetId}/scan`, config, { timeout })
  return res.data
}

// ── 新增 API: 扫描任务 ──

export async function getScans(targetId = null, limit = 50) {
  const params = { limit }
  if (targetId) params.target_id = targetId
  const res = await api.get('/scans', { params })
  return res.data
}

export async function getScanDetail(scanId) {
  const res = await api.get(`/scans/${scanId}`)
  return res.data
}

export async function getScanResults(scanId) {
  const res = await api.get(`/scans/${scanId}/results`)
  return res.data
}

export async function pauseScan(scanId) {
  const res = await api.post(`/scans/${scanId}/pause`)
  return res.data
}

export async function resumeScan(scanId) {
  const res = await api.post(`/scans/${scanId}/resume`)
  return res.data
}

export async function cancelScan(scanId) {
  const res = await api.post(`/scans/${scanId}/cancel`)
  return res.data
}

// ── 新增 API: 载荷管理 ──

export async function getPayloads(category = null) {
  const params = {}
  if (category) params.category = category
  const res = await api.get('/payloads', { params })
  return res.data
}

export async function getPayloadCategories() {
  const res = await api.get('/payloads/categories')
  return res.data
}

export async function getMutations() {
  const res = await api.get('/payloads/mutations')
  return res.data
}

export async function createPayload(data) {
  const res = await api.post('/payloads', data)
  return res.data
}

export async function deletePayload(payloadId) {
  const res = await api.delete(`/payloads/${payloadId}`)
  return res.data
}

export async function importPayloadsFromYaml() {
  const res = await api.post('/payloads/import-from-yaml')
  return res.data
}

// ── 新增 API: 报告 ──

export async function getScanReport(scanId, format = 'json') {
  const isText = format === 'markdown' || format === 'md' || format === 'html'
  const res = await api.get(`/report/scan/${scanId}`, {
    params: { format },
    responseType: isText ? 'text' : 'json',
  })
  return res.data
}

// ── 新增 API: 审计记录（兼容命名）──

export async function getRecords(params = {}) {
  const res = await api.get('/history', { params })
  return res.data
}

export async function getRecord(id) {
  const res = await api.get(`/history/${id}`)
  return res.data
}

export default api

// ── 投毒测试 API ──

export async function getPoisonDatasets() {
  const res = await api.get('/poison/datasets')
  return res.data
}

export async function startPoisonTest(dataset = 'all', maxCases = 0, concurrency = 3) {
  const res = await api.post('/poison/start', null, {
    params: { dataset, max_cases: maxCases, concurrency },
    timeout: 600000,
  })
  return res.data
}

export async function poisonTestSingle(inputText) {
  const res = await api.post('/poison/single', { input_text: inputText })
  return res.data
}
