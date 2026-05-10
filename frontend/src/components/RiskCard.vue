<template>
  <div :class="['risk-card', riskClass]">
    <div class="risk-score">{{ score }}</div>
    <div class="risk-level">{{ level }}</div>
    <div class="risk-categories">
      <span v-for="c in categories" :key="c" class="cat-tag">{{ c }}</span>
    </div>
  </div>
</template>

<script>
import { computed } from 'vue'
export default {
  name: 'RiskCard',
  props: {
    score: { type: Number, default: 0 },
    level: { type: String, default: '' },
    categories: { type: Array, default: () => [] }
  },
  setup(props) {
    const riskClass = computed(() => {
      const s = props.score
      if (s <= 30) return 'low'
      if (s <= 60) return 'medium'
      if (s <= 80) return 'high'
      return 'critical'
    })
    return { riskClass }
  }
}
</script>

<style scoped>
.risk-card { background: white; border-radius: 8px; padding: 24px; text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.risk-card.low { border-left: 4px solid #52c41a; }
.risk-card.medium { border-left: 4px solid #faad14; }
.risk-card.high { border-left: 4px solid #fa8c16; }
.risk-card.critical { border-left: 4px solid #f5222d; }
.risk-score { font-size: 48px; font-weight: 700; }
.low .risk-score { color: #52c41a; }
.medium .risk-score { color: #faad14; }
.high .risk-score { color: #fa8c16; }
.critical .risk-score { color: #f5222d; }
.risk-level { font-size: 16px; color: #666; margin: 4px 0 10px; }
.risk-categories { display: flex; flex-wrap: wrap; gap: 4px; justify-content: center; }
.cat-tag { background: #f0f0f0; padding: 2px 8px; border-radius: 3px; font-size: 12px; color: #666; }
</style>
