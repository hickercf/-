import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

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

export async function getStats() {
  const res = await api.get('/stats')
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
  const res = await api.post(`/targets/${targetId}/scan`, config)
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

export default api
