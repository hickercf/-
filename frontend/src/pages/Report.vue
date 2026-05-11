<template>
  <div class="report-page">
    <!-- 模式切换 -->
    <div class="mode-tabs">
      <button :class="['mode-tab', { active: mode === 'audit' }]" @click="mode = 'audit'">单条审计报告</button>
      <button :class="['mode-tab', { active: mode === 'scan' }]" @click="mode = 'scan'">扫描风控报告</button>
    </div>

    <!-- 审计报告模式 -->
    <div v-if="mode === 'audit'">
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

    <!-- 扫描报告模式 -->
    <div v-else>
      <div class="card">
        <h3>扫描风控报告</h3>
        <div class="search-row">
          <select v-model="selectedScan" class="scan-select">
            <option value="">-- 选择扫描任务 --</option>
            <option v-for="s in scans" :key="s.scan_id" :value="s.scan_id">
              {{ s.scan_id }} — {{ s.target_name || s.target_id }}
            </option>
          </select>
          <button @click="loadScanReport">查看报告</button>
          <button class="export-md" @click="exportScanReport('markdown')">导出 Markdown</button>
          <button class="export-html" @click="exportScanReport('html')">导出 HTML</button>
        </div>
      </div>

      <div v-if="scanReport" class="card">
        <h4>扫描概要</h4>
        <div class="summary-grid">
          <div class="summary-item">
            <span class="summary-label">扫描ID</span>
            <code>{{ scanReport.task?.scan_id }}</code>
          </div>
          <div class="summary-item">
            <span class="summary-label">靶标</span>
            <span>{{ scanReport.target?.name || scanReport.task?.target_id }}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">扫描模式</span>
            <span>{{ scanReport.task?.scan_mode }}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">载荷总数</span>
            <span>{{ scanReport.task?.total_payloads }}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">发现漏洞</span>
            <span class="vuln-count">{{ scanReport.vulnerabilities_found }}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">状态</span>
            <span :class="'status-badge ' + scanReport.task?.status">{{ scanReport.task?.status }}</span>
          </div>
        </div>

        <h4 style="margin-top:20px">漏洞详情 ({{ scanReport.vulnerabilities_found || 0 }})</h4>
        <table v-if="scanReport.results?.length" class="vuln-table">
          <thead>
            <tr><th>载荷ID</th><th>严重度</th><th>防线层</th><th>描述</th><th>修复建议</th></tr>
          </thead>
          <tbody>
            <tr v-for="r in scanReport.results.filter(x => x.is_vulnerability)" :key="r.id">
              <td><code>{{ r.payload_id }}</code></td>
              <td><span :class="'severity-tag ' + r.vulnerability_severity">{{ r.vulnerability_severity }}</span></td>
              <td>{{ r.defense_breaches?.map(b => b.layer).join('+') }}</td>
              <td class="desc-cell">{{ r.defense_breaches?.[0]?.description?.substring(0, 80) }}</td>
              <td class="sug-cell">{{ r.defense_breaches?.[0]?.suggestion?.substring(0, 80) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { getReport, getScans, getScanReport } from '../api/request.js'

export default {
  name: 'ReportPage',
  setup() {
    const mode = ref('audit')
    const recordId = ref('')
    const report = ref(null)
    const scans = ref([])
    const selectedScan = ref('')
    const scanReport = ref(null)

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

    async function loadScans() {
      try { scans.value = (await getScans(null, 50)).scans || [] } catch (e) { /* */ }
    }

    async function loadScanReport() {
      if (!selectedScan.value) return
      try {
        scanReport.value = await getScanReport(selectedScan.value, 'json')
      } catch (e) { alert('加载失败: ' + e.message) }
    }

    async function exportScanReport(format) {
      if (!selectedScan.value) return
      try {
        const resp = await getScanReport(selectedScan.value, format)
        const mime = format === 'html' ? 'text/html' : 'text/markdown'
        const ext = format === 'html' ? 'html' : 'md'
        const blob = new Blob([resp], { type: mime })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = `AgentFuzzer_ScanReport_${selectedScan.value}.${ext}`; a.click()
        URL.revokeObjectURL(url)
      } catch (e) { alert('导出失败: ' + e.message) }
    }

    onMounted(loadScans)

    return {
      mode, recordId, report, scans, selectedScan, scanReport,
      loadReport, exportReport, loadScanReport, exportScanReport,
    }
  }
}
</script>

<style scoped>
.report-page { max-width: 1000px; }
.card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.card h3, .card h4 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.search-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
input, select { padding: 6px 12px; border: 1px solid #d9d9d9; border-radius: 4px; }
input { width: 120px; }
.scan-select { min-width: 350px; }
button { padding: 6px 14px; border: none; background: #1890ff; color: white; border-radius: 4px; cursor: pointer; }
button:hover { opacity: 0.9; }
.export-md { background: #52c41a; }
.export-html { background: #faad14; }

.mode-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.mode-tab { padding: 8px 18px; border: 1px solid #d9d9d9; background: #f5f5f5; color: #666; cursor: pointer; border-radius: 6px 6px 0 0; font-size: 13px; }
.mode-tab.active { background: white; color: #1890ff; border-bottom-color: white; font-weight: 600; }

.report-content p { margin-bottom: 8px; font-size: 13px; }
.report-content code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-size: 12px; }

.summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
.summary-item { display: flex; flex-direction: column; }
.summary-label { font-size: 11px; color: #94a3b8; }
.summary-item span { font-size: 13px; }
.summary-item code { font-size: 11px; background: #f1f5f9; }
.vuln-count { color: #dc2626; font-weight: 600; }

.vuln-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }
.vuln-table th, .vuln-table td { padding: 6px 8px; text-align: left; border-bottom: 1px solid #e2e8f0; }
.vuln-table th { font-weight: 600; color: #64748b; background: #f8fafc; }
.desc-cell, .sug-cell { max-width: 200px; }

.severity-tag { font-size: 11px; padding: 1px 6px; border-radius: 3px; font-weight: 600; }
.severity-tag.critical { background: #fecaca; color: #dc2626; }
.severity-tag.high { background: #fed7aa; color: #ea580c; }
.severity-tag.medium { background: #fef08a; color: #ca8a04; }
.severity-tag.low { background: #dbeafe; color: #2563eb; }

.status-badge { font-size: 11px; padding: 2px 6px; border-radius: 10px; }
.status-badge.completed { background: #d1fae5; color: #059669; }
.status-badge.running { background: #dbeafe; color: #2563eb; }
.status-badge.failed { background: #fecaca; color: #dc2626; }
</style>
