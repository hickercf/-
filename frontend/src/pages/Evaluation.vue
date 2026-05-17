<template>
  <div class="eval-page">
    <div class="card">
      <h3>批量评测</h3>
      <p class="desc">运行测试集评估系统检测效果，对比规则检测、LLM检测和融合检测的性能。</p>
      <button class="run-btn" @click="runEval" :disabled="loading">
        {{ loading ? '评测中...' : '运行评测' }}
      </button>
    </div>
    <div v-if="result" class="results">
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-value">{{ result.total }}</div>
          <div class="metric-label">测试样例</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">{{ (result.extraction_success_rate * 100 || 0).toFixed(1) }}%</div>
          <div class="metric-label">抽取成功率</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">{{ (result.risk_level_accuracy * 100 || 0).toFixed(1) }}%</div>
          <div class="metric-label">等级准确率</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">{{ (result.high_risk_recall * 100 || 0).toFixed(1) }}%</div>
          <div class="metric-label">高危召回率</div>
        </div>
        <div class="metric-card" :class="{ danger: result.critical_miss_count > 0 }">
          <div class="metric-value">{{ result.critical_miss_count }}</div>
          <div class="metric-label">严重风险漏报</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">{{ (result.category_f1 ?? 0).toFixed(3) }}</div>
          <div class="metric-label">类别 F1</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">{{ (result.avg_response_time ?? 0).toFixed(2) }}s</div>
          <div class="metric-label">平均响应时间</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref } from 'vue'
import { runEvaluation } from '../api/request.js'

export default {
  name: 'EvalPage',
  setup() {
    const loading = ref(false)
    const result = ref(null)

    async function runEval() {
      loading.value = true
      try {
        result.value = await runEvaluation()
      } catch (e) {
        alert('评测失败: ' + e.message)
      } finally {
        loading.value = false
      }
    }

    return { loading, result, runEval }
  }
}
</script>

<style scoped>
.card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.card h3 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.desc { font-size: 13px; color: #666; margin-bottom: 16px; line-height: 1.6; }
.run-btn { padding: 10px 32px; background: linear-gradient(135deg, #1890ff, #096dd9); color: white; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
.run-btn:hover { opacity: 0.9; }
.run-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-top: 20px; }
.metric-card { background: white; border-radius: 8px; padding: 24px; text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,0.08); border-top: 3px solid #1890ff; }
.metric-card.danger { border-top-color: #f5222d; }
.metric-value { font-size: 32px; font-weight: 700; color: #333; margin-bottom: 4px; }
.metric-card.danger .metric-value { color: #f5222d; }
.metric-label { font-size: 12px; color: #999; }
</style>
