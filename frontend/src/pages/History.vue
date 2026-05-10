<template>
  <div class="history-page">
    <div class="card">
      <h3>审计历史记录</h3>
      <table v-if="records.length" class="history-table">
        <thead>
          <tr>
            <th>ID</th><th>追踪编号</th><th>类型</th><th>风险分数</th>
            <th>风险等级</th><th>策略</th><th>时间</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in records" :key="r.id">
            <td>{{ r.id }}</td>
            <td class="mono">{{ r.trace_id }}</td>
            <td>{{ typeMap[r.input_type] || r.input_type }}</td>
            <td><strong>{{ r.risk_score }}</strong></td>
            <td><span :class="'level-tag ' + getLevelClass(r.risk_score)">{{ r.risk_level }}</span></td>
            <td><span :class="'policy-tag ' + r.policy_action">{{ r.policy_action.toUpperCase() }}</span></td>
            <td>{{ r.created_at }}</td>
            <td><button class="detail-btn" @click="showDetail(r)">详情</button></td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">暂无审计记录</div>
    </div>
    <div v-if="detail" class="modal-overlay" @click.self="detail = null">
      <div class="modal">
        <div class="modal-header">
          <h3>审计详情 - {{ detail.trace_id }}</h3>
          <button class="close-btn" @click="detail = null">&times;</button>
        </div>
        <div class="modal-body">
          <div class="detail-grid">
            <div class="detail-item"><span class="label">风险分数</span><strong>{{ detail.risk_score }}</strong></div>
            <div class="detail-item"><span class="label">风险等级</span><span>{{ detail.risk_level }}</span></div>
            <div class="detail-item"><span class="label">策略</span><span>{{ detail.policy_decision?.action }}</span></div>
            <div class="detail-item"><span class="label">输入类型</span><span>{{ detail.input_type }}</span></div>
          </div>
          <div class="detail-section">
            <h4>原始输入</h4>
            <pre>{{ detail.input_content }}</pre>
          </div>
          <div class="detail-section">
            <h4>风险解释</h4>
            <p>{{ detail.reason }}</p>
          </div>
          <div class="detail-section">
            <h4>修复建议</h4>
            <p>{{ detail.suggestion }}</p>
          </div>
          <div class="detail-section">
            <h4>审计哈希</h4>
            <code>{{ detail.record_hash }}</code>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { getHistory, getHistoryDetail } from '../api/request.js'

export default {
  name: 'HistoryPage',
  setup() {
    const records = ref([])
    const detail = ref(null)
    const typeMap = { task: '任务', tool_log: '工具日志', command: '命令', code: '代码', prompt: 'Prompt' }

    async function loadHistory() {
      try {
        records.value = await getHistory(100)
      } catch (e) { console.error(e) }
    }

    async function showDetail(r) {
      try {
        detail.value = await getHistoryDetail(r.id)
      } catch (e) { console.error(e) }
    }

    function getLevelClass(score) {
      if (score <= 30) return 'low'
      if (score <= 60) return 'medium'
      if (score <= 80) return 'high'
      return 'critical'
    }

    onMounted(loadHistory)

    return { records, detail, typeMap, showDetail, getLevelClass }
  }
}
</script>

<style scoped>
.card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.card h3 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.history-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.history-table th, .history-table td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; text-align: left; }
.history-table th { background: #fafafa; font-weight: 600; color: #666; }
.history-table tr:hover { background: #fafafa; }
.mono { font-family: monospace; font-size: 12px; }
.level-tag { padding: 2px 8px; border-radius: 3px; font-size: 11px; }
.level-tag.low { background: #f6ffed; color: #52c41a; }
.level-tag.medium { background: #fffbe6; color: #faad14; }
.level-tag.high { background: #fff7e6; color: #fa8c16; }
.level-tag.critical { background: #fff1f0; color: #f5222d; }
.policy-tag { padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }
.policy-tag.pass { background: #f6ffed; color: #52c41a; }
.policy-tag.warn { background: #fffbe6; color: #faad14; }
.policy-tag.review { background: #fff7e6; color: #fa8c16; }
.policy-tag.block { background: #fff1f0; color: #f5222d; }
.detail-btn { padding: 3px 10px; border: 1px solid #1890ff; color: #1890ff; background: white; border-radius: 3px; cursor: pointer; font-size: 12px; }
.detail-btn:hover { background: #1890ff; color: white; }
.empty { text-align: center; padding: 40px; color: #999; }
.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; z-index: 100; }
.modal { background: white; border-radius: 8px; width: 700px; max-height: 80vh; overflow-y: auto; }
.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid #f0f0f0; }
.modal-header h3 { margin: 0; font-size: 16px; }
.close-btn { background: none; border: none; font-size: 24px; cursor: pointer; color: #999; }
.modal-body { padding: 20px; }
.detail-grid { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 12px; margin-bottom: 16px; }
.detail-item { display: flex; flex-direction: column; gap: 4px; }
.detail-item .label { font-size: 12px; color: #999; }
.detail-section { margin-bottom: 16px; }
.detail-section h4 { font-size: 13px; color: #666; margin-bottom: 6px; }
.detail-section pre { background: #f5f5f5; padding: 12px; border-radius: 4px; font-size: 13px; white-space: pre-wrap; }
.detail-section p { font-size: 13px; line-height: 1.7; color: #555; }
.detail-section code { background: #f5f5f5; padding: 4px 8px; border-radius: 3px; font-size: 12px; word-break: break-all; }
</style>
