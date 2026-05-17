<template>
  <div class="graph-card">
    <h3>{{ title }}</h3>

    <div v-if="mode === 'react' && reactSteps.length" class="react-list">
      <div
        v-for="(step, index) in reactSteps"
        :key="index"
        :class="['react-step', stepType(step), breachAt(step.step_index ?? index)?.severity || 'normal']"
      >
        <div class="step-index">{{ index + 1 }}</div>
        <div class="step-main">
          <div class="step-head">
            <span class="step-type">{{ stepTypeLabel(step) }}</span>
            <span v-if="breachAt(step.step_index ?? index)" class="step-breach">
              {{ breachAt(step.step_index ?? index).layer }} / {{ breachAt(step.step_index ?? index).severity }}
            </span>
          </div>
          <div class="step-body">
            <p v-if="step.thought"><strong>Thought:</strong> {{ step.thought }}</p>
            <p v-if="step.action"><strong>Action:</strong> {{ step.action }}</p>
            <p v-if="step.observation"><strong>Observation:</strong> {{ step.observation }}</p>
          </div>
        </div>
      </div>
    </div>

    <div v-else-if="nodes.length" class="chain-wrap">
      <div v-for="(node, index) in nodes" :key="node.id || index" class="chain-segment">
        <div :class="['node-card', riskClass(node)]">
          <div class="node-top">
            <span :class="['node-action', node.action === 'unknown' ? 'unknown' : '']">{{ node.action === 'unknown' ? '未识别操作' : (node.action || 'unknown') }}</span>
            <span v-if="node.tool && node.tool !== 'unknown'" class="node-tool">{{ node.tool }}</span>
          </div>
          <div class="node-body">
            <p v-if="node.object && node.object !== '-' && node.object !== 'unknown'"><strong>对象:</strong> {{ node.object }}</p>
            <p v-if="node.data_type && node.data_type !== 'unknown'"><strong>数据:</strong> {{ node.data_type }}</p>
            <p v-if="node.permission && node.permission !== 'unknown'"><strong>权限:</strong> {{ node.permission }}</p>
            <p v-if="node.destination && node.destination !== 'local' && node.destination !== 'unknown'"><strong>目标:</strong> {{ node.destination }}</p>
            <p v-if="node.evidence_text && node.evidence_text !== 'unknown'" class="node-evidence"><strong>证据:</strong> {{ node.evidence_text }}</p>
          </div>
        </div>

        <div v-if="index < nodes.length - 1" class="edge-block">
          <div class="edge-line"></div>
          <div class="edge-label">{{ edgeLabel(node, nodes[index + 1]) }}</div>
          <div class="edge-arrow">↓</div>
        </div>
      </div>
    </div>

    <p v-else class="empty-text">暂无可展示的行为链数据</p>

    <div v-if="mode !== 'react' && edges.length" class="edge-list">
      <div class="edge-list-title">边关系</div>
      <div v-for="(edge, index) in edges" :key="edge.source + '-' + edge.target + '-' + index" class="edge-item">
        <code>{{ edge.source }}</code>
        <span class="edge-relation">{{ edge.relation || 'then' }}</span>
        <code>{{ edge.target }}</code>
        <span v-if="edge.description" class="edge-desc">{{ edge.description }}</span>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'BehaviorChainGraph',
  props: {
    title: { type: String, default: '行为链路图' },
    nodes: { type: Array, default: () => [] },
    edges: { type: Array, default: () => [] },
    mode: { type: String, default: 'graph' },
    reactSteps: { type: Array, default: () => [] },
    breaches: { type: Array, default: () => [] },
  },
  setup(props) {
    function breachAt(index) {
      return props.breaches.find(b => b.step_index === index) || null
    }

    function riskClass(node) {
      if (node.permission === 'unauthorized' || node.destination === 'external') return 'critical'
      if (['delete', 'execute', 'override', 'leak'].includes(node.action)) return 'high'
      if (['send', 'upload', 'download'].includes(node.action)) return 'medium'
      return 'low'
    }

    function edgeLabel(currentNode, nextNode) {
      const matched = props.edges.find(edge => edge.source === currentNode.id && edge.target === nextNode.id)
      return matched?.relation || 'then'
    }

    function stepType(step) {
      if (step.type) return step.type
      if (step.thought) return 'thought'
      if (step.action) return 'action'
      return 'observation'
    }

    function stepTypeLabel(step) {
      const type = stepType(step)
      const labels = { thought: 'Thought', action: 'Action', observation: 'Observation' }
      return labels[type] || type
    }

    return {
      breachAt,
      riskClass,
      edgeLabel,
      stepType,
      stepTypeLabel,
    }
  },
}
</script>

<style scoped>
.graph-card {
  background: white;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 16px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.08);
}

.graph-card h3 {
  font-size: 15px;
  color: #333;
  margin-bottom: 14px;
  padding-bottom: 8px;
  border-bottom: 1px solid #f0f0f0;
}

.chain-wrap {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.chain-segment {
  display: flex;
  flex-direction: column;
}

.node-card {
  border: 1px solid #e8e8e8;
  border-left-width: 4px;
  border-radius: 8px;
  background: #fafafa;
  padding: 14px 16px;
}

.node-card.low { border-left-color: #52c41a; }
.node-card.medium { border-left-color: #faad14; }
.node-card.high { border-left-color: #fa8c16; }
.node-card.critical { border-left-color: #f5222d; background: #fff7f7; }

.node-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
}

.node-action {
  font-size: 16px;
  font-weight: 700;
  color: #222;
  text-transform: uppercase;
}

.node-action.unknown {
  color: #999;
  font-weight: 400;
  font-style: italic;
}

.node-tool {
  font-size: 12px;
  color: #666;
  background: #f0f0f0;
  border-radius: 999px;
  padding: 3px 10px;
}

.node-body p {
  margin: 4px 0;
  font-size: 13px;
  color: #555;
  line-height: 1.5;
}

.node-evidence {
  color: #777;
}

.edge-block {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 8px 0 10px;
}

.edge-line {
  width: 2px;
  height: 18px;
  background: #d9d9d9;
}

.edge-label {
  font-size: 12px;
  color: #666;
  background: #f5f5f5;
  border-radius: 999px;
  padding: 2px 8px;
  margin: 4px 0;
}

.edge-arrow {
  font-size: 16px;
  color: #999;
  line-height: 1;
}

.edge-list {
  margin-top: 16px;
  padding-top: 12px;
  border-top: 1px dashed #e8e8e8;
}

.edge-list-title {
  font-size: 13px;
  font-weight: 600;
  color: #333;
  margin-bottom: 8px;
}

.edge-item {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 6px;
  font-size: 12px;
  color: #666;
}

.edge-item code {
  background: #f5f5f5;
  border-radius: 4px;
  padding: 2px 6px;
}

.edge-relation {
  color: #1890ff;
  font-weight: 600;
}

.edge-desc {
  color: #999;
}

.react-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.react-step {
  display: flex;
  gap: 12px;
  align-items: stretch;
}

.step-index {
  width: 32px;
  min-width: 32px;
  height: 32px;
  border-radius: 50%;
  background: #1890ff;
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
}

.step-main {
  flex: 1;
  border: 1px solid #e8e8e8;
  border-left: 4px solid #1890ff;
  border-radius: 8px;
  padding: 12px 14px;
  background: #fafafa;
}

.react-step.action .step-main { border-left-color: #fa8c16; }
.react-step.observation .step-main { border-left-color: #52c41a; }
.react-step.critical .step-main { border-left-color: #f5222d; background: #fff1f0; }
.react-step.high .step-main { border-left-color: #fa8c16; background: #fff7e6; }
.react-step.medium .step-main { border-left-color: #faad14; }

.step-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 8px;
}

.step-type {
  font-weight: 700;
  color: #333;
}

.step-breach {
  font-size: 12px;
  color: #f5222d;
}

.step-body p {
  margin: 4px 0;
  font-size: 13px;
  color: #555;
}

.empty-text {
  color: #999;
  font-size: 13px;
}
</style>
