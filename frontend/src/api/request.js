import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

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

export async function getEvidenceChain() {
  const res = await api.get('/evidence-chain')
  return res.data
}

export async function runEvaluation() {
  const res = await api.post('/evaluate')
  return res.data
}

export default api
