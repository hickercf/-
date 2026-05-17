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
            <td><span :class="'policy-tag ' + (r.policy_action || 'unknown')">{{ (r.policy_action || 'UNKNOWN').toUpperCase() }}</span></td>
            <td>{{ r.created_at }}</td>
            <td><button class="detail-btn" @click="showDetail(r)">详情</button></td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">暂无审计记录</div>
    </div>

    <!-- 审计详情弹窗（合并 Trace 链路） -->
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

          <!-- 合并：行为链 Trace 时间线 -->
          <div v-if="traceEvents.length" class="detail-section">
            <h4>AgentTrace 链路</h4>
            <div class="timeline">
              <div
                v-for="(event, index) in traceEvents"
                :key="index"
                class="timeline-item"
                :class="{ 'high-risk': isHighRiskEvent(event) }"
              >
                <div class="timeline-marker" :class="event.event_type">
                  {{ index + 1 }}
                </div>
                <div class="timeline-content">
                  <div class="event-header">
                    <span class="event-type">{{ eventTypeLabel(event.event_type) }}</span>
                    <span v-if="event.tool" class="event-tool">{{ event.tool }}</span>
                  </div>
                  <div class="event-body">
                    <p v-if="event.action"><strong>动作:</strong> {{ event.action }}</p>
                    <p v-if="event.object"><strong>对象:</strong> {{ event.object }}</p>
                    <p v-if="event.data_type"><strong>数据类型:</strong> {{ event.data_type }}</p>
                    <p v-if="event.permission"><strong>权限:</strong> {{ event.permission }}</p>
                    <p v-if="event.destination"><strong>目标:</strong> {{ event.destination }}</p>
                    <p class="evidence"><strong>证据:</strong> {{ event.evidence }}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="detail-section">
            <h4>风险解释</h4>
            <p>{{ detail.reason }}</p>
          </div>
          <div class="detail-section">
            <h4>修复建议</h4>
            <p>{{ detail.suggestion }}</p>
          </div>

          <!-- 防线崩溃点 -->
          <div v-if="breaches.length" class="detail-section">
            <h4>防线崩溃点</h4>
            <div v-for="breach in breaches" :key="breach.layer + breach.step_index" class="breach-card" :class="breach.severity">
              <div class="breach-header">
                <span class="breach-layer">{{ breach.layer }}</span>
                <span class="breach-severity">{{ breach.severity }}</span>
              </div>
              <p class="breach-desc">{{ breach.description }}</p>
              <p class="breach-evidence">证据: {{ breach.evidence }}</p>
              <p class="breach-suggestion">建议: {{ breach.suggestion }}</p>
            </div>
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
import { ref, computed, onMounted } from 'vue'
import { getHistory, getHistoryDetail } from '../api/request.js'

export default {
  name: 'HistoryPage',
  setup() {
    const records = ref([])
    const detail = ref(null)
    const typeMap = { task: '任务', tool_log: '工具日志', command: '命令', code: '代码', prompt: 'Prompt' }

    async function loadHistory() {
      try {
        const response = await getHistory(100)
        records.value = response.records || []
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

    const traceEvents = computed(() => {
      if (!detail.value?.behavior_chain) return []
      const chain = detail.value.behavior_chain
      const nodes = chain.nodes || []
      return nodes.map((n, i) => ({
        event_id: `evt-${i}`,
        event_type: n.tool && n.tool !== 'unknown' ? 'tool_call' : 'message',
        tool: n.tool,
        action: n.action,
        object: n.object,
        data_type: n.data_type,
        permission: n.permission,
        destination: n.destination,
        evidence: n.evidence_text || '',
      }))
    })

    const breaches = computed(() => {
      return detail.value?.defense_breaches || []
    })

    function isHighRiskEvent(event) {
      const riskyActions = ['send', 'upload', 'leak', 'delete', 'execute', 'override']
      const riskyDataTypes = ['password', 'credential', 'token', 'api_key', 'personal_info']
      return (
        riskyActions.includes(event.action) ||
        riskyDataTypes.includes(event.data_type) ||
        event.permission === 'unauthorized' ||
        event.destination === 'external'
      )
    }

    function eventTypeLabel(type) {
      const labels = {
        message: '消息', plan: '计划', tool_select: '工具选择',
        tool_call: '工具调用', observation: '观察结果',
        data_flow: '数据流', output: '输出', policy: '策略'
      }
      return labels[type] || type
    }

    onMounted(loadHistory)

    return { records, detail, typeMap, showDetail, getLevelClass, traceEvents, breaches, isHighRiskEvent, eventTypeLabel }
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
.modal { background: white; border-radius: 8px; width: 800px; max-height: 85vh; overflow-y: auto; }
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

/* 时间线样式 */
.timeline { position: relative; padding-left: 30px; }
.timeline::before { content: ''; position: absolute; left: 15px; top: 0; bottom: 0; width: 2px; background: #e8e8e8; }
.timeline-item { position: relative; margin-bottom: 16px; }
.timeline-item.high-risk .timeline-content { border-left-color: #f5222d; background: #fff1f0; }
.timeline-marker {
  position: absolute; left: -23px; width: 28px; height: 28px;
  background: #1890ff; color: white; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 12px; font-weight: 600;
}
.timeline-marker.tool_call { background: #52c41a; }
.timeline-marker.observation { background: #faad14; }
.timeline-marker.data_flow { background: #f5222d; }
.timeline-marker.policy { background: #722ed1; }
.timeline-content {
  margin-left: 15px; padding: 10px 12px;
  border-left: 3px solid #1890ff; background: #fafafa;
  border-radius: 4px;
}
.event-header { display: flex; gap: 10px; margin-bottom: 6px; flex-wrap: wrap; }
.event-type { font-weight: 600; color: #1890ff; font-size: 13px; }
.event-tool { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
.event-body p { margin: 3px 0; font-size: 12px; }
.evidence { color: #666; font-style: italic; }

/* 防线崩溃卡片 */
.breach-card {
  margin-bottom: 10px; padding: 10px 12px;
  border-radius: 4px; border-left: 3px solid #faad14;
  background: #fffbe6;
}
.breach-card.critical { border-left-color: #f5222d; background: #fff1f0; }
.breach-card.high { border-left-color: #fa8c16; background: #fff7e6; }
.breach-header { display: flex; gap: 10px; margin-bottom: 4px; }
.breach-layer { font-weight: 600; font-size: 13px; }
.breach-severity { font-size: 11px; padding: 2px 6px; border-radius: 3px; background: #ff4d4f; color: white; }
.breach-card.high .breach-severity { background: #fa8c16; }
.breach-card.medium .breach-severity { background: #faad14; }
.breach-desc { margin: 4px 0; font-size: 13px; }
.breach-evidence, .breach-suggestion { font-size: 12px; color: #666; margin: 2px 0; }
</style>
