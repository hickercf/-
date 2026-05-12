<template>
  <div class="attack-trace-page">
    <div class="page-header">
      <h2>AgentTrace 链路追踪</h2>
      <p class="subtitle">展示 Agent 从输入到输出的完整执行轨迹，高亮高危工具调用和敏感数据流向</p>
    </div>

    <div class="controls">
      <div class="input-group">
        <label>选择审计记录:</label>
        <select v-model="selectedRecordId" @change="loadTrace">
          <option value="">请选择...</option>
          <option v-for="r in records" :key="r.id" :value="r.id">
            #{{ r.id }} - {{ r.input_type }} - {{ r.risk_level }} ({{ r.risk_score }}分)
          </option>
        </select>
      </div>
      <div class="input-group">
        <label>或输入 Trace ID:</label>
        <input v-model="traceIdInput" placeholder="输入 Trace ID" />
        <button @click="loadTraceById">加载</button>
      </div>
    </div>

    <div v-if="trace" class="trace-container">
      <!-- 基本信息 -->
      <div class="trace-header">
        <div class="trace-meta">
          <span class="trace-id">Trace ID: {{ trace.trace_id }}</span>
          <span class="trace-source">来源: {{ trace.source }}</span>
          <span class="trace-time">时间: {{ trace.created_at }}</span>
        </div>
        <div class="trace-input">
          <strong>用户输入:</strong> {{ trace.input_text }}
        </div>
      </div>

      <!-- 时间线 -->
      <div class="timeline">
        <div
          v-for="(event, index) in trace.events"
          :key="event.event_id"
          class="timeline-item"
          :class="{ 'high-risk': isHighRiskEvent(event) }"
        >
          <div class="timeline-marker" :class="event.event_type">
            {{ index + 1 }}
          </div>
          <div class="timeline-content">
            <div class="event-header">
              <span class="event-type">{{ eventTypeLabel(event.event_type) }}</span>
              <span class="event-actor">{{ actorLabel(event.actor) }}</span>
              <span v-if="event.tool" class="event-tool">{{ event.tool }}</span>
            </div>
            <div class="event-body">
              <p v-if="event.action"><strong>动作:</strong> {{ event.action }}</p>
              <p v-if="event.object"><strong>对象:</strong> {{ event.object }}</p>
              <p v-if="event.data_type"><strong>数据类型:</strong> {{ event.data_type }}</p>
              <p v-if="event.permission"><strong>权限:</strong> {{ event.permission }}</p>
              <p v-if="event.source || event.destination">
                <strong>数据流:</strong> {{ event.source || 'local' }} → {{ event.destination || 'local' }}
              </p>
              <p class="evidence"><strong>证据:</strong> {{ event.evidence }}</p>
            </div>
          </div>
        </div>
      </div>

      <!-- 最终输出 -->
      <div v-if="trace.final_output" class="final-output">
        <h4>最终输出</h4>
        <p>{{ trace.final_output }}</p>
      </div>

      <!-- 防线崩溃点 -->
      <div v-if="breaches.length" class="breaches-section">
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
    </div>

    <div v-else class="empty-state">
      <p>请选择一个审计记录或输入 Trace ID 查看 AgentTrace</p>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { getRecords, getRecord } from '../api/request.js'

export default {
  name: 'AttackTracePage',
  setup() {
    const records = ref([])
    const selectedRecordId = ref('')
    const traceIdInput = ref('')
    const trace = ref(null)
    const breaches = ref([])

    async function loadRecords() {
      try {
        const data = await getRecords({ limit: 50 })
        records.value = data.records || []
      } catch (e) {
        console.error('加载记录失败:', e)
      }
    }

    async function loadTrace() {
      if (!selectedRecordId.value) {
        trace.value = null
        breaches.value = []
        return
      }
      try {
        const record = await getRecord(selectedRecordId.value)
        if (record.behavior_chain) {
          trace.value = convertToTrace(record)
        }
        breaches.value = record.defense_breaches || []
      } catch (e) {
        console.error('加载 Trace 失败:', e)
      }
    }

    async function loadTraceById() {
      if (!traceIdInput.value) return
      // 在记录中查找
      const record = records.value.find(r => r.trace_id === traceIdInput.value)
      if (record) {
        selectedRecordId.value = record.id
        await loadTrace()
      }
    }

    function convertToTrace(record) {
      const chain = record.behavior_chain || {}
      const nodes = chain.nodes || []
      
      return {
        trace_id: record.trace_id,
        source: record.input_type || 'manual',
        agent_name: 'unknown',
        input_text: record.input_content || '',
        events: nodes.map((n, i) => ({
          event_id: `evt-${i}`,
          event_type: n.tool !== 'unknown' ? 'tool_call' : 'message',
          actor: n.actor || 'agent',
          tool: n.tool,
          action: n.action,
          object: n.object,
          data_type: n.data_type,
          permission: n.permission,
          destination: n.destination,
          evidence: n.evidence_text || '',
        })),
        final_output: '',
        created_at: record.created_at,
      }
    }

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

    function actorLabel(actor) {
      const labels = { user: '用户', agent: 'Agent', tool: '工具', system: '系统' }
      return labels[actor] || actor
    }

    onMounted(loadRecords)

    return {
      records,
      selectedRecordId,
      traceIdInput,
      trace,
      breaches,
      loadTrace,
      loadTraceById,
      isHighRiskEvent,
      eventTypeLabel,
      actorLabel,
    }
  }
}
</script>

<style scoped>
.attack-trace-page { max-width: 1200px; margin: 0 auto; }
.page-header { margin-bottom: 20px; }
.page-header h2 { margin: 0 0 8px; }
.subtitle { color: #666; font-size: 14px; }

.controls { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }
.input-group { display: flex; align-items: center; gap: 8px; }
.input-group label { font-weight: 500; }
.input-group select, .input-group input { padding: 6px 10px; border: 1px solid #d9d9d9; border-radius: 4px; }
.input-group button { padding: 6px 16px; background: #1890ff; color: white; border: none; border-radius: 4px; cursor: pointer; }

.trace-container { background: #fff; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
.trace-header { margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #f0f0f0; }
.trace-meta { display: flex; gap: 15px; margin-bottom: 10px; flex-wrap: wrap; }
.trace-meta span { font-size: 13px; color: #666; }
.trace-id { font-family: monospace; background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
.trace-input { padding: 10px; background: #f6ffed; border-left: 3px solid #52c41a; border-radius: 4px; }

.timeline { position: relative; padding-left: 30px; }
.timeline::before { content: ''; position: absolute; left: 15px; top: 0; bottom: 0; width: 2px; background: #e8e8e8; }
.timeline-item { position: relative; margin-bottom: 20px; }
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
  margin-left: 15px; padding: 12px 15px;
  border-left: 3px solid #1890ff; background: #fafafa;
  border-radius: 4px;
}
.event-header { display: flex; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
.event-type { font-weight: 600; color: #1890ff; }
.event-actor { color: #666; font-size: 13px; }
.event-tool { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
.event-body p { margin: 4px 0; font-size: 13px; }
.evidence { color: #666; font-style: italic; }

.final-output { margin-top: 20px; padding: 15px; background: #e6f7ff; border-radius: 4px; }
.final-output h4 { margin: 0 0 8px; color: #1890ff; }

.breaches-section { margin-top: 20px; }
.breaches-section h4 { margin-bottom: 12px; }
.breach-card {
  margin-bottom: 10px; padding: 12px 15px;
  border-radius: 4px; border-left: 3px solid #faad14;
  background: #fffbe6;
}
.breach-card.critical { border-left-color: #f5222d; background: #fff1f0; }
.breach-card.high { border-left-color: #fa8c16; background: #fff7e6; }
.breach-header { display: flex; gap: 10px; margin-bottom: 6px; }
.breach-layer { font-weight: 600; }
.breach-severity { font-size: 12px; padding: 2px 6px; border-radius: 3px; background: #ff4d4f; color: white; }
.breach-card.high .breach-severity { background: #fa8c16; }
.breach-card.medium .breach-severity { background: #faad14; }
.breach-desc { margin: 4px 0; }
.breach-evidence, .breach-suggestion { font-size: 12px; color: #666; margin: 2px 0; }

.empty-state { text-align: center; padding: 60px 20px; color: #999; }
</style>
