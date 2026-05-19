<template>
  <div class="scan-page">
    <div class="page-header">
      <h2>扫描控制台</h2>
      <div class="header-actions">
        <div class="mode-tabs">
          <button :class="['mode-tab', { active: pageMode === 'payload' }]" @click="pageMode = 'payload'">Payload 扫描</button>
          <button :class="['mode-tab', { active: pageMode === 'poison' }]" @click="pageMode = 'poison'">投毒测试</button>
        </div>
        <select id="scan-target-select" v-model="selectedTarget" class="target-select">
          <option value="">-- 选择靶标 Agent --</option>
          <option v-for="t in targets" :key="t.target_id" :value="t.target_id">{{ t.name }}</option>
        </select>
      </div>
    </div>
    <div v-if="errorMessage" class="error-banner">{{ errorMessage }}</div>

    <div class="scan-layout">
      <!-- 左侧: 配置 -->
      <div class="config-panel">

        <!-- ====== Payload 扫描模式 ====== -->
        <template v-if="pageMode === 'payload'">
        <div class="card">
          <h3>扫描配置</h3>
          <div class="form-group">
            <label>扫描模式</label>
            <div class="mode-group">
              <label v-for="m in scanModes" :key="m.value" :class="['mode-option', { active: config.scan_mode === m.value }]">
                <input type="radio" v-model="config.scan_mode" :value="m.value" />
                <div class="mode-info">
                  <span class="mode-name">{{ m.label }}</span>
                  <span class="mode-desc">{{ m.desc }}</span>
                </div>
              </label>
            </div>
          </div>
          <div class="form-group">
            <label>攻击类别</label>
            <div class="checkbox-group">
              <label v-for="c in categories" :key="c.id" class="checkbox-item">
                <input type="checkbox" :value="c.id" v-model="config.categories" />
                {{ c.label }}
              </label>
            </div>
          </div>
          <div class="form-group">
            <label>变异策略</label>
            <div class="checkbox-group">
              <label v-for="m in commonMutations" :key="m" class="checkbox-item">
                <input type="checkbox" :value="m" v-model="config.mutation_strategies" />
                {{ m }}
              </label>
            </div>
          </div>
          <div class="form-group">
            <label for="scan-rate-limit">速率限制 (req/s)</label>
            <input id="scan-rate-limit" type="number" v-model.number="config.rate_limit" min="0.1" max="10" step="0.1" />
          </div>
          <button class="btn-primary btn-block" @click="startNewScan" :disabled="!selectedTarget || scanning">
            {{ scanning ? '扫描中...' : '开始扫描' }}
          </button>
          <div v-if="activeScan" class="scan-actions">
            <button v-if="activeScan.status === 'running'" class="btn-sm" @click="pauseCurrentScan">暂停</button>
            <button v-if="activeScan.status === 'paused'" class="btn-sm" @click="resumeCurrentScan">恢复</button>
            <button v-if="['running','paused','pending'].includes(activeScan.status)" class="btn-sm btn-danger" @click="cancelCurrentScan">取消</button>
          </div>
        </div>
        </template>

        <!-- ====== 投毒测试模式 ====== -->
        <template v-if="pageMode === 'poison'">
        <div class="card">
          <h3>投毒配置</h3>
          <div class="form-group">
            <label>测试规模</label>
            <select v-model="poisonConfig.batchPreset" :disabled="poisonRunning">
              <option value="small">小批量测试 (30条)</option>
              <option value="medium">中批量测试 (300条)</option>
              <option value="large">大批量测试 (800条)</option>
            </select>
          </div>
          <div class="form-group">
            <label>并发数</label>
            <input type="number" v-model.number="poisonConfig.concurrency" min="1" max="10" :disabled="poisonRunning" />
          </div>
          <button class="btn-primary btn-block" @click="startPoisonTest" :disabled="!selectedTarget || poisonRunning">
            {{ poisonRunning ? `测试中... (${poisonProgress.percent}%)` : '开始投毒测试' }}
          </button>
          <button v-if="poisonRunning" class="btn-secondary btn-block" style="margin-top:6px" @click="poisonRunning = false">停止</button>
        </div>

        <!-- 投毒进度 -->
        <div v-if="poisonRunning || poisonProgress.percent > 0" class="card">
          <h3>测试进度</h3>
          <div class="progress-bar-wrap">
            <div class="progress-bar" :style="{ width: poisonProgress.percent + '%' }"></div>
          </div>
          <div class="progress-info">
            <span>{{ poisonProgress.done }} / {{ poisonProgress.total }} 条</span>
            <span>{{ poisonProgress.percent }}%</span>
            <span>已用 {{ poisonProgress.elapsedSec }}s</span>
          </div>
        </div>

        <!-- 投毒结果统计 -->
        <div v-if="poisonResults.length > 0" class="card">
          <h3>投毒统计</h3>
          <div class="poison-stats-grid">
            <div class="poison-stat"><span class="poison-num">{{ poisonReport.total }}</span><span class="poison-label">总用例</span></div>
            <div class="poison-stat hit"><span class="poison-num">{{ poisonReport.attack_success_count }}</span><span class="poison-label">攻击成功</span></div>
            <div class="poison-stat def"><span class="poison-num">{{ poisonReport.defense_success_count }}</span><span class="poison-label">防御成功</span></div>
            <div class="poison-stat rate"><span class="poison-num">{{ poisonReport.attack_success_rate }}%</span><span class="poison-label">攻击成功率</span></div>
          </div>
        </div>
        </template>

        <!-- 自定义 Payload -->
        <div class="card">
          <h3>自定义 Payload</h3>
          <div class="form-group">
            <label>Payload ID</label>
            <input v-model="customPayload.payload_id" placeholder="如: CUSTOM-001" />
          </div>
          <div class="form-group">
            <label>标题</label>
            <input v-model="customPayload.title" placeholder="Payload 标题" />
          </div>
          <div class="form-group">
            <label>分类</label>
            <select v-model="customPayload.category">
              <option value="">-- 选择分类 --</option>
              <option v-for="c in categories" :key="c.id" :value="c.id">{{ c.label }}</option>
            </select>
          </div>
          <div class="form-group">
            <label>严重度</label>
            <select v-model="customPayload.severity">
              <option value="low">低</option>
              <option value="medium">中</option>
              <option value="high">高</option>
              <option value="critical">严重</option>
            </select>
          </div>
          <div class="form-group">
            <label>模板内容</label>
            <textarea v-model="customPayload.template" rows="4" placeholder="输入攻击载荷模板..."></textarea>
          </div>
          <button class="btn-secondary btn-block" @click="createCustomPayload" :disabled="!customPayload.payload_id || !customPayload.title || !customPayload.category || !customPayload.template">
            添加自定义 Payload
          </button>
        </div>
      </div>

      <!-- 右侧: 结果 -->
      <div class="result-panel">

        <!-- ====== Payload 扫描结果 ====== -->
        <template v-if="pageMode === 'payload'">
        <!-- 扫描进度 -->
        <div v-if="activeScan" class="card">
          <h3>扫描进度 — {{ activeScan.scan_id }}</h3>
          <div class="progress-bar-wrap">
            <div class="progress-bar" :style="{ width: progressPct + '%' }"></div>
          </div>
          <div class="progress-info">
            <span>{{ activeScan.completed_payloads }} / {{ activeScan.total_payloads }}</span>
            <span>发现漏洞: <strong class="vuln-count">{{ activeScan.vulnerabilities_found }}</strong></span>
            <span :class="'status-badge ' + activeScan.status">{{ statusLabel(activeScan.status) }}</span>
          </div>
        </div>

        <!-- 实时攻击链路 -->
        <div v-if="latestResults.length" class="card">
          <h3>最近攻击链路</h3>
          <div v-for="r in latestResults.slice(0, 5)" :key="r.id" class="result-item">
            <div class="result-header">
              <span class="payload-id">{{ r.payload_id }}</span>
              <span :class="['severity-tag', resultStatusClass(r)]">{{ resultStatusLabel(r) }}</span>
              <span class="resp-time">{{ r.response_time_ms }}ms</span>
            </div>
            <div class="variant-text">{{ (r.variant || '').substring(0, 150) }}{{ r.variant?.length > 150 ? '...' : '' }}</div>
            <div v-if="r.defense_breaches?.length" class="breaches">
              <div v-for="b in r.defense_breaches" :key="b.layer + b.step_index" :class="['breach-item', b.severity]">
                <strong>{{ b.layer }}</strong> — {{ b.description }}
                <div class="breach-evidence">证据: {{ b.evidence?.substring(0, 100) }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- 历史扫描 -->
        <div class="card">
          <h3>历史扫描任务</h3>
          <table v-if="scanHistory.length" class="scan-table">
            <thead>
              <tr><th>扫描 ID</th><th>靶标</th><th>模式</th><th>进度</th><th>漏洞</th><th>状态</th><th>操作</th></tr>
            </thead>
            <tbody>
              <tr v-for="s in scanHistory" :key="s.scan_id">
                <td><code>{{ s.scan_id }}</code></td>
                <td>{{ s.target_name || s.target_id }}</td>
                <td>{{ s.scan_mode }}</td>
                <td>{{ s.completed_payloads }}/{{ s.total_payloads }}</td>
                <td>{{ s.vulnerabilities_found }}</td>
                <td><span :class="'status-badge ' + s.status">{{ statusLabel(s.status) }}</span></td>
                <td>
                  <button class="btn-sm" @click="viewScanDetail(s)">详情</button>
                </td>
              </tr>
            </tbody>
          </table>
          <p v-else class="empty-text">暂无扫描记录</p>
        </div>
        </template>

        <!-- ====== 投毒测试结果 ====== -->
        <template v-if="pageMode === 'poison'">
        <!-- 过滤 -->
        <div v-if="poisonResults.length > 0" class="filter-bar">
          <button :class="['filter-btn', { active: poisonFilter === 'all' }]" @click="poisonFilter = 'all'">全部 ({{ poisonResults.length }})</button>
          <button :class="['filter-btn', { active: poisonFilter === 'success' }]" @click="poisonFilter = 'success'">攻击成功 ({{ poisonResults.filter(r => r.attack_success).length }})</button>
          <button :class="['filter-btn', { active: poisonFilter === 'failed' }]" @click="poisonFilter = 'failed'">防御成功 ({{ poisonResults.filter(r => !r.attack_success).length }})</button>
        </div>

        <!-- 投毒结果列表 -->
        <div v-if="filteredPoisonResults.length > 0" class="card">
          <div class="poison-list">
            <div
              v-for="r in filteredPoisonResults"
              :key="r.case_id"
              :class="['poison-result-item', r.severity, { expanded: expandedCase === r.case_id }]"
              @click="expandedCase = expandedCase === r.case_id ? null : r.case_id"
            >
              <div class="poison-result-header">
                <span :class="['poison-badge', r.attack_success ? 'hit' : 'def']">{{ r.attack_success ? '攻击成功' : '防御成功' }}</span>
                <span class="poison-case-id">{{ r.case_id }}</span>
                <span class="poison-case-summary">{{ r.summary }}</span>
                <span class="poison-case-time">{{ r.elapsed_ms }}ms</span>
              </div>
              <div v-if="expandedCase === r.case_id" class="poison-result-detail">
                <div class="detail-block"><b>攻击输入:</b><pre>{{ r.input_text }}</pre></div>
                <div class="detail-block"><b>Agent 响应:</b><pre>{{ r.agent_output || '(无输出)' }}</pre></div>
                <div v-if="r.evidence" class="detail-block"><b>判定证据:</b><pre>{{ r.evidence }}</pre></div>
                <div class="detail-meta"><span>类型: {{ r.attack_type || '-' }}</span><span>严重度: {{ r.severity }}</span></div>
              </div>
            </div>
          </div>
        </div>

        <!-- 空状态 -->
        <div v-if="!poisonRunning && poisonResults.length === 0" class="card">
          <p class="empty-text">选择靶标 Agent，然后点击"开始投毒测试"</p>
          <p class="empty-text" style="font-size:12px;color:#cbd5e1">请确保沙箱 Agent 已启动 (端口 18080)</p>
        </div>
        </template>

      </div>
    </div>

    <!-- 扫描详情弹窗 -->
    <div v-if="scanDetail" class="modal-overlay" @click.self="scanDetail = null">
      <div class="modal scan-detail-modal">
        <h3>扫描详情 — {{ scanDetail.task?.scan_id }}</h3>
        <div class="scan-summary">
          <div class="stat-item">
            <span class="stat-num">{{ scanDetail.task?.total_payloads || 0 }}</span>
            <span class="stat-label">总载荷</span>
          </div>
          <div class="stat-item">
            <span class="stat-num vuln">{{ scanDetail.task?.vulnerabilities_found || 0 }}</span>
            <span class="stat-label">发现漏洞</span>
          </div>
          <div class="stat-item">
            <span class="stat-num">{{ scanDetail.stats?.total_results || 0 }}</span>
            <span class="stat-label">已完成</span>
          </div>
        </div>
        <div v-if="scanDetail.results?.length" class="results-list">
          <div v-for="r in scanDetail.results" :key="r.id" class="result-item">
            <div class="result-header">
              <span class="payload-id">{{ r.payload_id }}</span>
              <span :class="['severity-tag', resultStatusClass(r)]">
                {{ resultStatusLabel(r) }}
              </span>
            </div>
            <div v-if="r.defense_breaches?.length">
              <div v-for="b in r.defense_breaches" :key="b.layer" :class="['breach-item', b.severity]">
                <strong>{{ b.layer }}</strong>: {{ b.description }}
                <span class="breach-suggestion">→ {{ b.suggestion }}</span>
              </div>
            </div>
          </div>
        </div>
        <button class="btn-secondary" @click="scanDetail = null">关闭</button>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { getTargets, getScans, getScanDetail, startTargetScan, pauseScan, resumeScan, cancelScan, createPayload, startPoisonTest } from '../api/request.js'

export default {
  name: 'ScanConsole',
  setup() {
    const targets = ref([])
    const selectedTarget = ref('')
    const scanning = ref(false)
    const activeScan = ref(null)
    const scanHistory = ref([])
    const scanDetail = ref(null)
    const latestResults = ref([])
    const errorMessage = ref('')
    const pageMode = ref('poison')
    const poisonRunning = ref(false)
    const poisonResults = ref([])
    const poisonFilter = ref('all')
    const expandedCase = ref(null)
    const poisonProgress = reactive({ done: 0, total: 0 })
    const poisonReport = reactive({ total: 0, attack_success_count: 0, defense_success_count: 0, attack_success_rate: 0 })
    const poisonConfig = reactive({ batchPreset: 'small', concurrency: 3 })
    let ws = null
    let pollTimer = null

    const config = reactive({
      scan_mode: 'standard',
      categories: [],
      mutation_strategies: [],
      rate_limit: 1.0,
    })

    const customPayload = reactive({
      payload_id: '',
      title: '',
      category: '',
      severity: 'medium',
      template: '',
      params: [],
      mutations: [],
      cwe_reference: '',
    })

    const scanModes = [
      { value: 'quick', label: '快速扫描', desc: 'Top-50 高危害载荷，~2 min' },
      { value: 'standard', label: '标准扫描', desc: '全部高/中危害载荷，~10 min' },
      { value: 'deep', label: '深度扫描', desc: '全量载荷+全变异策略，~60 min' },
      { value: 'targeted', label: '定向扫描', desc: '仅指定攻击类别' },
    ]

    const categories = [
      { id: 'prompt_injection', label: 'Prompt注入' },
      { id: 'role_play_bypass', label: '角色扮演' },
      { id: 'encoding_bypass', label: '编码绕过' },
      { id: 'language_confusion', label: '多语言混淆' },
      { id: 'data_exfiltration', label: '数据外泄' },
      { id: 'privilege_escalation', label: '权限提升' },
      { id: 'tool_abuse', label: '工具滥用' },
      { id: 'chain_of_thought_hijack', label: '思维链劫持' },
      { id: 'multi_turn_attack', label: '多轮攻击' },
      { id: 'context_overflow', label: '上下文溢出' },
    ]

    const commonMutations = ['base64_full', 'unicode_escape', 'mixed_lang_cn_en', 'zero_width_separator', 'case_variation']

    const progressPct = computed(() => {
      if (!activeScan.value || !activeScan.value.total_payloads) return 0
      return Math.round((activeScan.value.completed_payloads / activeScan.value.total_payloads) * 100)
    })

    const loadTargets = async () => {
      try {
        errorMessage.value = ''
        targets.value = (await getTargets()).targets || []
      } catch (e) {
        errorMessage.value = '靶标加载失败: ' + (e.response?.data?.detail || e.message)
      }
    }

    const loadScanHistory = async () => {
      try {
        errorMessage.value = ''
        scanHistory.value = (await getScans(null, 30)).scans || []
      } catch (e) {
        errorMessage.value = '扫描历史加载失败: ' + (e.response?.data?.detail || e.message)
      }
    }

    const restoreActiveScan = async () => {
      await loadScanHistory()
      const resumable = scanHistory.value.find(s => ['running', 'paused', 'pending'].includes(s.status))
      if (!resumable) return

      activeScan.value = resumable
      scanning.value = ['running', 'pending'].includes(resumable.status)
      await refreshActiveScan()

      if (activeScan.value && ['running', 'pending'].includes(activeScan.value.status)) {
        if (pollTimer) clearInterval(pollTimer)
        pollTimer = setInterval(refreshActiveScan, 2000)
      }
    }

    const refreshActiveScan = async () => {
      if (!activeScan.value) return
      try {
        const data = await getScanDetail(activeScan.value.scan_id)
        activeScan.value = data.task
        latestResults.value = data.results || []
        if (['completed', 'failed', 'cancelled'].includes(data.task?.status)) {
          clearInterval(pollTimer)
          activeScan.value = null
          scanning.value = false
          await loadScanHistory()
        }
      } catch (e) {
        errorMessage.value = '扫描进度刷新失败: ' + (e.response?.data?.detail || e.message)
      }
    }

    const startNewScan = async () => {
      if (!selectedTarget.value) return
      scanning.value = true
      try {
        const result = await startTargetScan(selectedTarget.value, { ...config })
        activeScan.value = { scan_id: result.scan_id, completed_payloads: 0, total_payloads: result.total_payloads || 0, vulnerabilities_found: 0, status: 'running' }
        await loadScanHistory()
        if (pollTimer) clearInterval(pollTimer)
        pollTimer = setInterval(refreshActiveScan, 2000)
      } catch (e) {
        alert('启动扫描失败: ' + (e.response?.data?.detail || e.message))
        scanning.value = false
      }
    }

    const pauseCurrentScan = async () => {
      if (!activeScan.value) return
      try {
        await pauseScan(activeScan.value.scan_id)
        activeScan.value.status = 'paused'
      } catch (e) {
        alert('暂停扫描失败: ' + (e.response?.data?.detail || e.message))
      }
    }

    const resumeCurrentScan = async () => {
      if (!activeScan.value) return
      try {
        await resumeScan(activeScan.value.scan_id)
        activeScan.value.status = 'running'
        scanning.value = true
        if (pollTimer) clearInterval(pollTimer)
        pollTimer = setInterval(refreshActiveScan, 2000)
      } catch (e) {
        alert('恢复扫描失败: ' + (e.response?.data?.detail || e.message))
      }
    }

    const cancelCurrentScan = async () => {
      if (!activeScan.value) return
      try {
        await cancelScan(activeScan.value.scan_id)
        activeScan.value.status = 'cancelled'
        scanning.value = false
        clearInterval(pollTimer)
        await loadScanHistory()
      } catch (e) {
        alert('取消扫描失败: ' + (e.response?.data?.detail || e.message))
      }
    }

    const viewScanDetail = async (s) => {
      try {
        scanDetail.value = await getScanDetail(s.scan_id)
      } catch (e) {
        errorMessage.value = '扫描详情加载失败: ' + (e.response?.data?.detail || e.message)
      }
    }

    const createCustomPayload = async () => {
      if (!customPayload.payload_id || !customPayload.template) return
      try {
        await createPayload({ ...customPayload })
        alert('自定义 Payload 添加成功')
        // 清空表单
        customPayload.payload_id = ''
        customPayload.title = ''
        customPayload.category = ''
        customPayload.severity = 'medium'
        customPayload.template = ''
      } catch (e) {
        alert('添加失败: ' + (e.response?.data?.detail || e.message))
      }
    }

    const statusLabel = (s) => ({
      pending: '等待中', running: '运行中', completed: '已完成',
      paused: '已暂停', cancelled: '已取消', failed: '失败'
    }[s] || s)

    const resultStatusClass = (r) => r?.react_trace?.error ? 'error' : (r?.vulnerability_severity || 'safe')
    const resultStatusLabel = (r) => r?.react_trace?.error ? '执行失败' : (r?.vulnerability_severity || '安全')

    const filteredPoisonResults = computed(() => {
      if (poisonFilter.value === 'success') return poisonResults.value.filter(r => r.attack_success)
      if (poisonFilter.value === 'failed') return poisonResults.value.filter(r => !r.attack_success)
      return poisonResults.value
    })

    const startPoisonTest = async () => {
      if (!selectedTarget.value) return
      const presetMap = {
        small: { dataset: 'test_cases', max_cases: 30 },
        medium: { dataset: 'advanced', max_cases: 300 },
        large: { dataset: 'advanced', max_cases: 800 },
      }
      const preset = presetMap[poisonConfig.batchPreset]
      if (!preset) {
        errorMessage.value = '请选择测试规模'
        return
      }

      poisonRunning.value = true
      poisonResults.value = []
      expandedCase.value = null
      poisonProgress.done = 0
      poisonProgress.total = preset.max_cases
      poisonProgress.percent = 0
      poisonProgress.elapsedSec = 0
      errorMessage.value = ''

      const secPerCase = 1.8
      const estimatedTotalSec = preset.max_cases * secPerCase / poisonConfig.concurrency
      const startTime = Date.now()
      let timer = null
      timer = setInterval(() => {
        const elapsed = (Date.now() - startTime) / 1000
        poisonProgress.elapsedSec = Math.floor(elapsed)
        const estimatedPercent = Math.min((elapsed / estimatedTotalSec) * 100, 95)
        poisonProgress.percent = Math.floor(estimatedPercent)
      }, 300)

      try {
        const data = await startTargetScan(selectedTarget.value, {
          scan_mode: 'standard',
          dataset: preset.dataset,
          max_cases: preset.max_cases,
          concurrency: poisonConfig.concurrency,
        })
        clearInterval(timer)
        poisonProgress.percent = 100
        poisonProgress.done = data.total
        poisonResults.value = data.results || []
        poisonReport.total = data.total
        poisonReport.attack_success_count = data.attack_success_count
        poisonReport.defense_success_count = data.defense_success_count
        poisonReport.attack_success_rate = data.attack_success_rate
      } catch (e) {
        clearInterval(timer)
        errorMessage.value = '投毒测试失败: ' + (e.response?.data?.detail || e.message)
      } finally {
        poisonRunning.value = false
      }
    }

    onMounted(async () => {
      await loadTargets()
      await restoreActiveScan()
    })
    onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })

    return {
      targets, selectedTarget, scanning, activeScan, scanHistory, scanDetail, latestResults, errorMessage,
      config, scanModes, categories, commonMutations, progressPct,
      customPayload, createCustomPayload,
      startNewScan, pauseCurrentScan, resumeCurrentScan, cancelCurrentScan, viewScanDetail, statusLabel, resultStatusClass, resultStatusLabel,
      pageMode, poisonRunning, poisonResults, poisonFilter, expandedCase, poisonProgress, poisonReport, poisonConfig,
      filteredPoisonResults, startPoisonTest,
    }
  }
}
</script>

<style scoped>
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.target-select { padding: 8px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; min-width: 250px; }
.error-banner { margin-bottom: 16px; padding: 10px 12px; border: 1px solid #fecaca; border-radius: 6px; background: #fef2f2; color: #b91c1c; font-size: 13px; }
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
.scan-layout { display: grid; grid-template-columns: 320px 1fr; gap: 20px; }
.card { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); padding: 16px; margin-bottom: 16px; }
.card h3 { margin: 0 0 12px; font-size: 15px; }
.form-group { margin-bottom: 14px; }
.form-group label { display: block; font-size: 12px; font-weight: 600; color: #64748b; margin-bottom: 4px; }
.form-group input { width: 100%; padding: 7px 10px; border: 1px solid #cbd5e1; border-radius: 5px; font-size: 13px; }

.mode-group { display: flex; flex-direction: column; gap: 6px; }
.mode-option { display: flex; align-items: flex-start; gap: 8px; padding: 8px; border: 1px solid #e2e8f0; border-radius: 6px; cursor: pointer; }
.mode-option.active { border-color: #2563eb; background: #eff6ff; }
.mode-info { display: flex; flex-direction: column; }
.mode-name { font-size: 13px; font-weight: 600; }
.mode-desc { font-size: 11px; color: #94a3b8; }

.checkbox-group { display: flex; flex-wrap: wrap; gap: 8px; }
.checkbox-item { font-size: 12px; display: flex; align-items: center; gap: 3px; cursor: pointer; }

.btn-block { width: 100%; }
.scan-actions { display: flex; gap: 6px; margin-top: 10px; }

.progress-bar-wrap { background: #e2e8f0; border-radius: 8px; height: 12px; overflow: hidden; margin-bottom: 10px; }
.progress-bar { background: linear-gradient(90deg, #2563eb, #7c3aed); height: 100%; transition: width 0.5s; border-radius: 8px; }
.progress-info { display: flex; justify-content: space-between; font-size: 13px; color: #64748b; gap: 12px; }
.progress-info span { white-space: nowrap; }
.vuln-count { color: #dc2626; }

.result-item { padding: 10px; margin-bottom: 8px; background: #f8fafc; border-radius: 6px; border-left: 3px solid #e2e8f0; }
.result-header { display: flex; gap: 8px; align-items: center; margin-bottom: 4px; }
.payload-id { font-weight: 600; font-size: 12px; color: #2563eb; }
.severity-tag { font-size: 11px; padding: 1px 6px; border-radius: 3px; font-weight: 600; }
.severity-tag.critical { background: #fecaca; color: #dc2626; }
.severity-tag.high { background: #fed7aa; color: #ea580c; }
.severity-tag.medium { background: #fef08a; color: #ca8a04; }
.severity-tag.low { background: #dbeafe; color: #2563eb; }
.severity-tag.safe { background: #d1fae5; color: #059669; }
.severity-tag.error { background: #e5e7eb; color: #4b5563; }
.resp-time { font-size: 11px; color: #94a3b8; margin-left: auto; }
.variant-text { font-size: 12px; color: #64748b; margin-bottom: 4px; word-break: break-all; }

.breaches { margin-top: 6px; }
.breach-item { font-size: 12px; padding: 6px 8px; margin: 4px 0; border-radius: 4px; }
.breach-item.critical { background: #fef2f2; border-left: 3px solid #dc2626; }
.breach-item.high { background: #fff7ed; border-left: 3px solid #ea580c; }
.breach-item.medium { background: #fefce8; border-left: 3px solid #ca8a04; }
.breach-evidence { font-size: 11px; color: #94a3b8; margin-top: 2px; }
.breach-suggestion { font-size: 11px; color: #059669; display: block; }

.scan-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.scan-table th, .scan-table td { padding: 8px; text-align: left; border-bottom: 1px solid #e2e8f0; }
.scan-table th { font-weight: 600; color: #64748b; font-size: 12px; }
.status-badge { font-size: 11px; padding: 2px 6px; border-radius: 10px; }
.status-badge.running { background: #dbeafe; color: #2563eb; }
.status-badge.completed { background: #d1fae5; color: #059669; }
.status-badge.paused { background: #fef08a; color: #ca8a04; }
.status-badge.failed { background: #fecaca; color: #dc2626; }
.status-badge.cancelled { background: #f1f5f9; color: #64748b; }

.scan-summary { display: flex; gap: 20px; margin-bottom: 16px; }
.stat-item { text-align: center; }
.stat-num { font-size: 28px; font-weight: 700; display: block; color: #2563eb; }
.stat-num.vuln { color: #dc2626; }
.stat-label { font-size: 12px; color: #94a3b8; }

.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; z-index: 100; }
.modal { background: #fff; border-radius: 12px; padding: 24px; max-height: 85vh; overflow-y: auto; }
.scan-detail-modal { width: 800px; }

.btn-primary { background: #2563eb; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
.btn-primary:hover { background: #1d4ed8; }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-secondary { background: #e2e8f0; color: #475569; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
.btn-secondary:hover { background: #cbd5e1; }
.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-sm { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; }
.btn-danger { color: #dc2626; border-color: #fecaca; }
.empty-text { text-align: center; color: #94a3b8; padding: 20px; }
.form-group textarea { width: 100%; padding: 7px 10px; border: 1px solid #cbd5e1; border-radius: 5px; font-size: 13px; resize: vertical; }
.form-group select { width: 100%; padding: 7px 10px; border: 1px solid #cbd5e1; border-radius: 5px; font-size: 13px; background: white; }

/* Mode tabs */
.mode-tabs { display: flex; gap: 4px; }
.mode-tab { padding: 6px 14px; border: 1px solid #cbd5e1; border-radius: 6px; background: #f8fafc; cursor: pointer; font-size: 13px; color: #475569; }
.mode-tab.active { background: #3b82f6; color: #fff; border-color: #3b82f6; }

/* Poison stats */
.poison-stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.poison-stat { text-align: center; padding: 10px; border-radius: 6px; background: #f8fafc; }
.poison-stat .poison-num { display: block; font-size: 22px; font-weight: 700; }
.poison-stat .poison-label { font-size: 11px; color: #64748b; }
.poison-stat.hit .poison-num { color: #ef4444; }
.poison-stat.def .poison-num { color: #22c55e; }
.poison-stat.rate .poison-num { color: #f59e0b; }

/* Filter bar */
.filter-bar { display: flex; gap: 8px; margin-bottom: 12px; }
.filter-btn { padding: 5px 12px; border: 1px solid #cbd5e1; border-radius: 5px; background: #f8fafc; cursor: pointer; font-size: 12px; color: #475569; }
.filter-btn.active { background: #3b82f6; color: #fff; border-color: #3b82f6; }

/* Poison result items */
.poison-list { display: flex; flex-direction: column; gap: 6px; }
.poison-result-item { border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 12px; cursor: pointer; transition: all 0.15s; }
.poison-result-item:hover { box-shadow: 0 2px 6px rgba(0,0,0,0.08); }
.poison-result-item.hit { border-left: 3px solid #ef4444; }
.poison-result-item.def { border-left: 3px solid #22c55e; }
.poison-result-header { display: flex; align-items: center; gap: 10px; font-size: 13px; }
.poison-badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; color: #fff; }
.poison-badge.hit { background: #ef4444; }
.poison-badge.def { background: #22c55e; }
.poison-case-id { font-family: monospace; color: #64748b; font-size: 12px; }
.poison-case-summary { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.poison-case-time { color: #94a3b8; font-size: 11px; }
.poison-result-detail { margin-top: 10px; padding-top: 10px; border-top: 1px solid #e2e8f0; }
.detail-block { margin-bottom: 8px; }
.detail-block b { font-size: 12px; color: #475569; }
.detail-block pre { margin: 4px 0 0; padding: 8px; background: #f8fafc; border-radius: 4px; font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 150px; overflow-y: auto; }
.detail-meta { display: flex; gap: 16px; font-size: 11px; color: #94a3b8; }
</style>
