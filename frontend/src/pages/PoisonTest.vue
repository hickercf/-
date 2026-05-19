<template>
  <div class="poison-page">
    <div class="page-header">
      <h2>自动化投毒测试</h2>
      <p class="desc">向沙箱 Agent 批量发送攻击用例，观察每条攻击的实际效果</p>
    </div>

    <!-- 控制面板 -->
    <div class="control-panel">
      <div class="control-row">
        <div class="control-group">
          <label>数据集</label>
          <select v-model="dataset" :disabled="running">
            <option value="all">全部 (180条)</option>
            <option value="test_cases">基础测试 (30条)</option>
            <option value="prompt_attacks">Prompt攻击 (100条)</option>
            <option value="adversarial">对抗样本 (50条)</option>
          </select>
        </div>
        <div class="control-group">
          <label>最大用例数</label>
          <input type="number" v-model.number="maxCases" min="0" :disabled="running" placeholder="0=全部" />
        </div>
        <div class="control-group">
          <label>并发数</label>
          <input type="number" v-model.number="concurrency" min="1" max="10" :disabled="running" />
        </div>
        <button class="btn-primary" @click="startTest" :disabled="running">
          {{ running ? `测试中... (${progress.done}/${progress.total})` : '开始投毒测试' }}
        </button>
        <button class="btn-secondary" v-if="running" @click="running = false">停止</button>
      </div>
    </div>

    <!-- 结果统计 -->
    <div class="stats-bar" v-if="results.length > 0">
      <div class="stat-card stat-total">
        <span class="stat-num">{{ report.total }}</span>
        <span class="stat-label">总用例</span>
      </div>
      <div class="stat-card stat-success">
        <span class="stat-num">{{ report.attack_success_count }}</span>
        <span class="stat-label">攻击成功</span>
      </div>
      <div class="stat-card stat-defended">
        <span class="stat-num">{{ report.defense_success_count }}</span>
        <span class="stat-label">防御成功</span>
      </div>
      <div class="stat-card stat-rate">
        <span class="stat-num">{{ report.attack_success_rate }}%</span>
        <span class="stat-label">攻击成功率</span>
      </div>
      <div class="stat-card stat-time">
        <span class="stat-num">{{ report.total_time_s }}s</span>
        <span class="stat-label">总耗时</span>
      </div>
    </div>

    <!-- 过滤 -->
    <div class="filter-bar" v-if="results.length > 0">
      <button :class="['filter-btn', { active: filter === 'all' }]" @click="filter = 'all'">全部</button>
      <button :class="['filter-btn', { active: filter === 'success' }]" @click="filter = 'success'">攻击成功</button>
      <button :class="['filter-btn', { active: filter === 'failed' }]" @click="filter = 'failed'">防御成功</button>
      <button :class="['filter-btn', { active: filter === 'error' }]" @click="filter = 'error'">错误</button>
    </div>

    <!-- 结果列表 -->
    <div class="results-list" v-if="filteredResults.length > 0">
      <div
        v-for="r in filteredResults"
        :key="r.case_id"
        :class="['result-card', r.severity, { expanded: expandedId === r.index }]"
        @click="toggleExpand(r.index)"
      >
        <div class="result-header">
          <span :class="['result-badge', r.attack_success ? 'attack-success' : 'attack-failed']">
            {{ r.attack_success ? '攻击成功' : '防御成功' }}
          </span>
          <span class="result-id">{{ r.case_id }}</span>
          <span class="result-summary">{{ r.summary }}</span>
          <span class="result-time">{{ r.elapsed_ms }}ms</span>
        </div>

        <div class="result-detail" v-if="expandedId === r.index">
          <div class="detail-section">
            <h4>攻击输入</h4>
            <pre class="detail-text input-text">{{ r.input_text }}</pre>
          </div>

          <div class="detail-section">
            <h4>Agent 响应</h4>
            <pre class="detail-text output-text">{{ r.agent_output || '(无输出)' }}</pre>
          </div>

          <div class="detail-section" v-if="r.evidence">
            <h4>判定证据</h4>
            <pre class="detail-text evidence-text">{{ r.evidence }}</pre>
          </div>

          <div class="detail-section" v-if="r.agent_trace_events && r.agent_trace_events.length > 0">
            <h4>Agent 行为链 ({{ r.agent_trace_events.length }} 步)</h4>
            <div class="trace-timeline">
              <div
                v-for="(evt, ei) in r.agent_trace_events"
                :key="ei"
                :class="['trace-step', evt.event_type]"
              >
                <span class="step-type">{{ evt.event_type }}</span>
                <span class="step-tool" v-if="evt.tool">{{ evt.tool }}</span>
                <span class="step-perm" v-if="evt.permission" :class="evt.permission">
                  {{ evt.permission }}
                </span>
                <span class="step-evidence">{{ evt.evidence }}</span>
              </div>
            </div>
          </div>

          <div class="detail-meta">
            <span>类型: {{ r.attack_type || '无' }}</span>
            <span>严重度: {{ r.severity }}</span>
            <span>耗时: {{ r.elapsed_ms }}ms</span>
            <span>预期: {{ r.expected }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 空状态 -->
    <div class="empty-state" v-if="!running && results.length === 0">
      <p>点击"开始投毒测试"向沙箱 Agent 发送攻击用例</p>
      <p class="hint">请确保沙箱 Agent 已启动 (端口 18080)</p>
    </div>
  </div>
</template>

<script>
import { ref, computed } from 'vue'
import { startPoisonTest, getPoisonDatasets } from '../api/request'

export default {
  name: 'PoisonTestPage',
  setup() {
    const dataset = ref('all')
    const maxCases = ref(0)
    const concurrency = ref(3)
    const running = ref(false)
    const results = ref([])
    const expandedId = ref(null)
    const filter = ref('all')
    const progress = ref({ done: 0, total: 0 })

    const report = ref({
      total: 0,
      attack_success_count: 0,
      defense_success_count: 0,
      error_count: 0,
      attack_success_rate: 0,
      total_time_s: 0,
    })

    const filteredResults = computed(() => {
      if (filter.value === 'all') return results.value
      if (filter.value === 'success') return results.value.filter(r => r.attack_success)
      if (filter.value === 'failed') return results.value.filter(r => !r.attack_success && r.severity !== 'error')
      if (filter.value === 'error') return results.value.filter(r => r.severity === 'error')
      return results.value
    })

    function toggleExpand(index) {
      expandedId.value = expandedId.value === index ? null : index
    }

    async function startTest() {
      running.value = true
      results.value = []
      expandedId.value = null
      progress.value = { done: 0, total: 0 }

      try {
        const data = await startPoisonTest(dataset.value, maxCases.value, concurrency.value)
        results.value = data.results || []
        report.value = {
          total: data.total,
          attack_success_count: data.attack_success_count,
          defense_success_count: data.defense_success_count,
          error_count: data.error_count,
          attack_success_rate: data.attack_success_rate,
          total_time_s: data.total_time_s,
        }
        progress.value = { done: data.total, total: data.total }
      } catch (e) {
        console.error('投毒测试失败:', e)
        alert('投毒测试失败: ' + (e.response?.data?.detail || e.message))
      } finally {
        running.value = false
      }
    }

    return {
      dataset, maxCases, concurrency, running,
      results, report, expandedId, filter, progress,
      filteredResults, toggleExpand, startTest,
    }
  }
}
</script>

<style scoped>
.poison-page { padding: 0; }
.page-header { margin-bottom: 20px; }
.page-header h2 { margin: 0 0 6px; font-size: 20px; }
.desc { color: #888; font-size: 13px; margin: 0; }

.control-panel {
  background: #1a1a2e; border-radius: 8px; padding: 16px 20px; margin-bottom: 16px;
}
.control-row { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
.control-group { display: flex; flex-direction: column; gap: 4px; }
.control-group label { font-size: 12px; color: #aaa; }
.control-group select, .control-group input {
  background: #2a2a4a; border: 1px solid #3a3a5a; color: #eee;
  padding: 8px 12px; border-radius: 6px; font-size: 13px; min-width: 120px;
}
.btn-primary {
  background: linear-gradient(135deg, #e74c3c, #c0392b); color: white;
  border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer;
  font-size: 13px; font-weight: 600; white-space: nowrap;
}
.btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
.btn-secondary {
  background: #3a3a5a; color: #ccc; border: none; padding: 8px 16px;
  border-radius: 6px; cursor: pointer; font-size: 13px;
}

.stats-bar {
  display: flex; gap: 12px; margin-bottom: 16px;
}
.stat-card {
  flex: 1; background: #1a1a2e; border-radius: 8px; padding: 12px 16px;
  display: flex; flex-direction: column; align-items: center;
}
.stat-num { font-size: 24px; font-weight: 700; }
.stat-label { font-size: 12px; color: #888; margin-top: 2px; }
.stat-total .stat-num { color: #eee; }
.stat-success .stat-num { color: #e74c3c; }
.stat-defended .stat-num { color: #2ecc71; }
.stat-rate .stat-num { color: #f39c12; }
.stat-time .stat-num { color: #3498db; }

.filter-bar { display: flex; gap: 6px; margin-bottom: 12px; }
.filter-btn {
  background: #2a2a4a; color: #aaa; border: 1px solid #3a3a5a;
  padding: 6px 14px; border-radius: 4px; cursor: pointer; font-size: 12px;
}
.filter-btn.active { background: #3a3a6a; color: #fff; border-color: #6a6aaa; }

.results-list { display: flex; flex-direction: column; gap: 6px; }

.result-card {
  background: #1e1e36; border-radius: 6px; cursor: pointer;
  border-left: 4px solid #3a3a5a; transition: all 0.15s;
}
.result-card.critical { border-left-color: #e74c3c; }
.result-card.high { border-left-color: #e67e22; }
.result-card.medium { border-left-color: #f1c40f; }
.result-card.safe { border-left-color: #2ecc71; }
.result-card.error { border-left-color: #95a5a6; }

.result-header {
  display: flex; align-items: center; gap: 10px; padding: 10px 14px;
}
.result-badge {
  font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px;
  white-space: nowrap;
}
.attack-success { background: #e74c3c33; color: #e74c3c; }
.attack-failed { background: #2ecc7133; color: #2ecc71; }
.result-id { font-size: 12px; color: #888; font-family: monospace; min-width: 50px; }
.result-summary { flex: 1; font-size: 13px; color: #ddd; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.result-time { font-size: 11px; color: #666; font-family: monospace; }

.result-detail {
  border-top: 1px solid #2a2a4a; padding: 14px; background: #161630;
}
.detail-section { margin-bottom: 12px; }
.detail-section h4 { font-size: 12px; color: #888; margin: 0 0 6px; }
.detail-text {
  background: #0e0e22; border-radius: 4px; padding: 10px; font-size: 12px;
  color: #ccc; white-space: pre-wrap; word-break: break-all; margin: 0;
  max-height: 200px; overflow-y: auto;
}
.input-text { border-left: 3px solid #e74c3c; }
.output-text { border-left: 3px solid #3498db; }
.evidence-text { border-left: 3px solid #f39c12; }

.trace-timeline { display: flex; flex-direction: column; gap: 3px; }
.trace-step {
  display: flex; gap: 8px; align-items: center; font-size: 11px;
  padding: 4px 8px; background: #0e0e22; border-radius: 3px;
}
.step-type {
  background: #2a2a4a; padding: 1px 6px; border-radius: 2px;
  color: #aaa; font-family: monospace; font-size: 10px;
}
.step-tool { color: #3498db; font-family: monospace; }
.step-perm { font-size: 10px; padding: 1px 4px; border-radius: 2px; }
.step-perm.unauthorized { background: #e74c3c33; color: #e74c3c; }
.step-perm.authorized { background: #2ecc7133; color: #2ecc71; }
.step-evidence { color: #888; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.detail-meta {
  display: flex; gap: 16px; font-size: 11px; color: #666; padding-top: 8px;
  border-top: 1px solid #2a2a4a;
}

.empty-state {
  text-align: center; padding: 60px 20px; color: #666;
}
.empty-state .hint { font-size: 13px; color: #555; margin-top: 8px; }
</style>
