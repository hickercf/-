<template>
  <div class="report-page">
    <div class="card">
      <h3>可信审计报告</h3>
      <div class="search-row">
        <input v-model="recordId" type="number" placeholder="输入记录 ID" />
        <button @click="loadReport">查看报告</button>
        <button class="export-md" @click="exportReport('markdown')">导出 Markdown</button>
        <button class="export-html" @click="exportReport('html')">导出 HTML</button>
      </div>
    </div>
    <div v-if="report" class="report-content card">
      <h4>审计结论</h4>
      <p><strong>追踪编号：</strong>{{ report.trace_id }}</p>
      <p><strong>风险分数：</strong>{{ report.risk_score }}</p>
      <p><strong>风险等级：</strong>{{ report.risk_level }}</p>
      <p><strong>处置策略：</strong>{{ report.policy_decision?.action }}</p>
      <p><strong>审计哈希：</strong><code>{{ report.record_hash }}</code></p>
      <p v-if="report.evidence_chain_valid !== undefined"><strong>审计链状态：</strong>{{ report.evidence_chain_valid ? '完整' : '异常' }}</p>
    </div>
  </div>
</template>

<script>
import { ref } from 'vue'
import { getReport } from '../api/request.js'

export default {
  name: 'ReportPage',
  setup() {
    const recordId = ref('')
    const report = ref(null)

    async function loadReport() {
      if (!recordId.value) return
      try {
        report.value = await getReport(recordId.value, 'json')
      } catch (e) { alert('加载失败: ' + e.message) }
    }

    async function exportReport(format) {
      if (!recordId.value) return
      try {
        const resp = await getReport(recordId.value, format)
        const mime = format === 'html' ? 'text/html' : 'text/markdown'
        const ext = format === 'html' ? 'html' : 'md'
        const blob = new Blob([resp], { type: mime })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = `AgentGuard_Report_${recordId.value}.${ext}`; a.click()
        URL.revokeObjectURL(url)
      } catch (e) { alert('导出失败: ' + e.message) }
    }

    return { recordId, report, loadReport, exportReport }
  }
}
</script>

<style scoped>
.report-page { max-width: 900px; }
.card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.card h3, .card h4 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.search-row { display: flex; gap: 8px; align-items: center; }
input { padding: 6px 12px; border: 1px solid #d9d9d9; border-radius: 4px; width: 120px; }
button { padding: 6px 14px; border: none; background: #1890ff; color: white; border-radius: 4px; cursor: pointer; }
button:hover { opacity: 0.9; }
.export-md { background: #52c41a; }
.export-html { background: #faad14; }
.report-content p { margin-bottom: 8px; font-size: 13px; }
.report-content code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
</style>
