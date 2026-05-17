<template>
  <div class="report-page">
    <div class="page-header">
      <h2>风控报告中心</h2>
      <div class="header-actions">
        <select v-model="selectedScan" @change="loadReport" class="scan-select">
          <option value="">-- 选择扫描任务 --</option>
          <option v-for="s in scans" :key="s.scan_id" :value="s.scan_id">
            {{ s.scan_id }} — {{ s.target_name || s.target_id }}
          </option>
        </select>
      </div>
    </div>

    <div v-if="!report" class="empty">
      <p>{{ errorMessage || '选择一个扫描任务查看风控报告' }}</p>
    </div>

    <div v-else class="report-content">
      <!-- 扫描概要 -->
      <div class="card summary-card">
        <h3>扫描概要</h3>
        <div class="summary-grid">
          <div class="summary-item">
            <span class="summary-label">靶标名称</span>
            <span class="summary-value">{{ report.task?.target_name || report.task?.target_id }}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">扫描模式</span>
            <span class="summary-value">{{ report.task?.scan_mode }}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">载荷总数</span>
            <span class="summary-value">{{ report.task?.total_payloads }}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">发现漏洞</span>
            <span class="summary-value vuln-count">{{ report.task?.vulnerabilities_found }}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">扫描时间</span>
            <span class="summary-value">{{ report.task?.started_at }}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">状态</span>
            <span :class="'status-badge ' + report.task?.status">{{ statusLabel(report.task?.status) }}</span>
          </div>
        </div>
      </div>

      <!-- 防线评估 -->
      <div class="card" v-if="defenseStats">
        <h3>五层防线命中分布</h3>
        <div class="defense-grid">
          <div v-for="(stat, layer) in defenseStats" :key="layer" class="defense-card" :class="layer.toLowerCase()">
            <div class="defense-layer">{{ layer }}</div>
            <div class="defense-rate">{{ stat.rate }}%</div>
            <div class="defense-detail">{{ stat.breached }}/{{ stat.total }} 漏洞载荷命中</div>
            <div class="defense-bar-wrap">
              <div class="defense-bar" :style="{ width: stat.rate + '%' }"></div>
            </div>
          </div>
        </div>
      </div>

      <!-- 漏洞清单 -->
      <div class="card" v-if="vulnerabilities.length">
        <h3>漏洞清单 ({{ vulnerabilities.length }})</h3>
        <table class="vuln-table">
          <thead>
            <tr>
              <th>#</th><th>载荷 ID</th><th>防线层</th><th>严重度</th><th>CWE</th><th>描述</th><th>修复建议</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(v, i) in vulnerabilities" :key="i">
              <td>{{ i + 1 }}</td>
              <td><code>{{ v.payload_id }}</code></td>
              <td><span class="layer-tag">{{ v.layer }}</span></td>
              <td><span :class="'severity-tag ' + v.severity">{{ v.severity }}</span></td>
              <td>{{ v.cwe_id }}</td>
              <td class="desc-cell">{{ v.description }}</td>
              <td class="sug-cell">{{ v.suggestion }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 严重度分布 -->
      <div class="card" v-if="severityDist">
        <h3>漏洞严重度分布</h3>
        <div class="severity-bars">
          <div v-for="sev in ['critical','high','medium','low']" :key="sev" class="severity-row">
            <span class="sev-label" :class="sev">{{ sev }}</span>
            <div class="sev-bar-wrap">
              <div class="sev-bar" :class="sev" :style="{ width: (severityDist[sev] || 0) / Math.max(vulnTotal, 1) * 100 + '%' }"></div>
            </div>
            <span class="sev-count">{{ severityDist[sev] || 0 }}</span>
          </div>
        </div>
      </div>

      <!-- 导出按钮 -->
      <div class="export-section">
        <button class="btn-primary" @click="exportReport('markdown')">导出 Markdown 报告</button>
        <button class="btn-secondary" @click="exportReport('html')">导出 HTML 报告</button>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed, onMounted } from 'vue'
import { getScans, getScanDetail, getScanReport } from '../api/request.js'

export default {
  name: 'VulnReport',
  setup() {
    const scans = ref([])
    const selectedScan = ref('')
    const report = ref(null)
    const errorMessage = ref('')
    const payloadResults = computed(() => report.value?.payload_results || [])

    const vulnerabilities = computed(() => {
      return payloadResults.value
        .filter(r => r.is_vulnerability)
        .map(r => {
          const breaches = r.defense_breaches || []
          const primary = breaches[0] || {}
          const layers = [...new Set(breaches.map(b => b.layer).filter(Boolean))].join('+')
          return {
            payload_id: r.payload_id,
            layer: layers,
            severity: r.vulnerability_severity,
            cwe_id: primary.cwe_id || '',
            description: primary.description || '',
            suggestion: primary.suggestion || '',
            evidence: primary.evidence || '',
          }
        })
    })

    const vulnTotal = computed(() => vulnerabilities.value.length)

    const severityDist = computed(() => {
      return report.value?.stats?.severity_distribution || { critical: 0, high: 0, medium: 0, low: 0 }
    })

    const defenseStats = computed(() => {
      const distribution = report.value?.stats?.defense_layer_distribution
      if (!distribution) return null
      const total = report.value?.stats?.vulnerabilities_found || vulnerabilities.value.length
      const stats = {}
      for (const layer of ['L1', 'L2', 'L3', 'L4', 'L5']) {
        const breached = distribution[layer] || 0
        stats[layer] = {
          breached,
          total,
          rate: total > 0 ? Math.round((breached / total) * 100) : 0,
        }
      }
      return stats
    })

    const loadScans = async () => {
      try {
        errorMessage.value = ''
        scans.value = (await getScans(null, 50)).scans || []
      } catch (e) {
        errorMessage.value = '扫描任务加载失败: ' + (e.response?.data?.detail || e.message)
      }
    }

    const loadReport = async () => {
      if (!selectedScan.value) { report.value = null; return }
      try {
        errorMessage.value = ''
        report.value = null
        report.value = await getScanDetail(selectedScan.value)
      } catch (e) {
        errorMessage.value = '报告加载失败: ' + (e.response?.data?.detail || e.message)
      }
    }

    const exportReport = async (format) => {
      if (!selectedScan.value) return
      try {
        const content = await getScanReport(selectedScan.value, format)
        const blob = new Blob([content], { type: format === 'html' ? 'text/html' : 'text/markdown' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = `report-${selectedScan.value}.${format === 'html' ? 'html' : 'md'}`
        a.click(); URL.revokeObjectURL(url)
      } catch (e) { alert('导出失败') }
    }

    const statusLabel = (s) => ({
      pending: '等待中', running: '运行中', completed: '已完成',
      paused: '已暂停', cancelled: '已取消', failed: '失败'
    }[s] || s)

    onMounted(loadScans)

    return {
      scans, selectedScan, report, errorMessage, vulnerabilities, vulnTotal, severityDist, defenseStats,
      loadReport, exportReport, statusLabel,
    }
  }
}
</script>

<style scoped>
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.scan-select { padding: 8px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; min-width: 350px; }
.empty { text-align: center; padding: 60px; color: #94a3b8; }

.card { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); padding: 20px; margin-bottom: 20px; }
.card h3 { margin: 0 0 14px; font-size: 16px; }

.summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.summary-item { display: flex; flex-direction: column; }
.summary-label { font-size: 12px; color: #94a3b8; }
.summary-value { font-size: 14px; font-weight: 600; color: #1e293b; }
.summary-value.vuln-count { color: #dc2626; font-size: 18px; }

.defense-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
.defense-card { text-align: center; padding: 12px; border-radius: 8px; background: #f8fafc; }
.defense-layer { font-weight: 700; font-size: 14px; margin-bottom: 6px; }
.defense-rate { font-size: 24px; font-weight: 700; color: #059669; }
.defense-detail { font-size: 11px; color: #94a3b8; margin: 4px 0; }
.defense-bar-wrap { background: #e2e8f0; border-radius: 4px; height: 6px; overflow: hidden; }
.defense-bar { background: #059669; height: 100%; border-radius: 4px; transition: width 0.5s; }

.vuln-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.vuln-table th, .vuln-table td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #e2e8f0; }
.vuln-table th { font-weight: 600; color: #64748b; font-size: 12px; background: #f8fafc; }
.desc-cell, .sug-cell { max-width: 250px; font-size: 12px; }
.layer-tag { font-size: 11px; padding: 1px 5px; border-radius: 3px; background: #ede9fe; color: #7c3aed; }

.severity-tag { font-size: 11px; padding: 2px 6px; border-radius: 3px; font-weight: 600; }
.severity-tag.critical { background: #fecaca; color: #dc2626; }
.severity-tag.high { background: #fed7aa; color: #ea580c; }
.severity-tag.medium { background: #fef08a; color: #ca8a04; }
.severity-tag.low { background: #dbeafe; color: #2563eb; }

.severity-bars { display: flex; flex-direction: column; gap: 8px; }
.severity-row { display: flex; align-items: center; gap: 10px; }
.sev-label { width: 60px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
.sev-label.critical { color: #dc2626; } .sev-label.high { color: #ea580c; }
.sev-label.medium { color: #ca8a04; } .sev-label.low { color: #2563eb; }
.sev-bar-wrap { flex: 1; background: #e2e8f0; border-radius: 4px; height: 16px; overflow: hidden; }
.sev-bar { height: 100%; border-radius: 4px; transition: width 0.5s; }
.sev-bar.critical { background: #dc2626; } .sev-bar.high { background: #ea580c; }
.sev-bar.medium { background: #f59e0b; } .sev-bar.low { background: #2563eb; }
.sev-count { width: 30px; font-size: 13px; font-weight: 600; text-align: right; }

.status-badge { font-size: 12px; padding: 2px 8px; border-radius: 10px; }
.status-badge.completed { background: #d1fae5; color: #059669; }
.status-badge.failed { background: #fecaca; color: #dc2626; }
.status-badge.running { background: #dbeafe; color: #2563eb; }

.export-section { display: flex; gap: 10px; margin-top: 20px; }
.btn-primary { background: #2563eb; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-size: 13px; }
.btn-primary:hover { background: #1d4ed8; }
.btn-secondary { background: #e2e8f0; color: #475569; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-size: 13px; }
</style>
