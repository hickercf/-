<template>
  <div class="policy-card card">
    <h3>策略裁决</h3>
    <div :class="['policy-action', decision.action]">{{ policyLabel }}</div>
    <p class="policy-reason">{{ decision.reason }}</p>
    <div v-if="advice.length" class="advice-list">
      <div class="advice-title">最小权限建议：</div>
      <ul><li v-for="a in advice" :key="a">{{ a }}</li></ul>
    </div>
  </div>
</template>

<script>
import { computed } from 'vue'
export default {
  name: 'PolicyDecision',
  props: {
    decision: { type: Object, default: () => ({ action: 'pass', reason: '', least_privilege_advice: [] }) }
  },
  setup(props) {
    const policyLabel = computed(() => {
      const map = { pass: '放行 (PASS)', warn: '警告 (WARN)', review: '人工复核 (REVIEW)', block: '阻断 (BLOCK)' }
      return map[props.decision.action] || ''
    })
    const advice = computed(() => props.decision.least_privilege_advice || [])
    return { policyLabel, advice }
  }
}
</script>

<style scoped>
.card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.card h3 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.policy-action { font-size: 20px; font-weight: 700; text-transform: uppercase; margin-bottom: 8px; }
.policy-action.pass { color: #52c41a; }
.policy-action.warn { color: #faad14; }
.policy-action.review { color: #fa8c16; }
.policy-action.block { color: #f5222d; }
.policy-reason { font-size: 13px; color: #666; line-height: 1.6; }
.advice-title { font-size: 13px; color: #333; margin: 8px 0 4px; font-weight: 600; }
.advice-list ul { padding-left: 16px; font-size: 12px; color: #666; }
.advice-list li { margin-bottom: 3px; }
</style>
