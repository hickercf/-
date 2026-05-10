<template>
  <div class="stats-page">
    <div class="stats-grid">
      <div class="card">
        <h3>总审计次数</h3>
        <div class="big-number">{{ stats.total_count || 0 }}</div>
      </div>
      <div class="card">
        <h3>风险等级分布</h3>
        <div ref="riskLevelRef" class="chart-box"></div>
      </div>
      <div class="card">
        <h3>策略裁决分布</h3>
        <div ref="policyRef" class="chart-box"></div>
      </div>
      <div class="card">
        <h3>风险类别分布</h3>
        <div ref="categoryRef" class="chart-box"></div>
      </div>
      <div class="card full">
        <h3>规则命中 Top 10</h3>
        <div ref="topRulesRef" class="chart-box"></div>
      </div>
      <div class="card full">
        <h3>最近风险分数趋势</h3>
        <div ref="trendRef" class="chart-box"></div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, nextTick } from 'vue'
import { getStats } from '../api/request.js'
import * as echarts from 'echarts'

export default {
  name: 'StatsPage',
  setup() {
    const stats = ref({})
    const riskLevelRef = ref(null)
    const policyRef = ref(null)
    const categoryRef = ref(null)
    const topRulesRef = ref(null)
    const trendRef = ref(null)

    const colors = ['#52c41a', '#faad14', '#fa8c16', '#f5222d']

    async function loadStats() {
      try {
        stats.value = await getStats()
        await nextTick()
        renderCharts()
      } catch (e) { console.error(e) }
    }

    function renderCharts() {
      const s = stats.value

      const rl = s.risk_level_distribution || {}
      renderPie(riskLevelRef, [
        { name: '低风险', value: rl['低风险'] || 0 },
        { name: '中风险', value: rl['中风险'] || 0 },
        { name: '高风险', value: rl['高风险'] || 0 },
        { name: '严重风险', value: rl['严重风险'] || 0 },
      ], colors)

      const pd = s.policy_distribution || {}
      renderPie(policyRef, [
        { name: 'PASS', value: pd['pass'] || 0 },
        { name: 'WARN', value: pd['warn'] || 0 },
        { name: 'REVIEW', value: pd['review'] || 0 },
        { name: 'BLOCK', value: pd['block'] || 0 },
      ], colors)

      const cd = s.risk_category_distribution || {}
      const catData = Object.entries(cd).map(([name, value]) => ({ name, value }))
      renderPie(categoryRef, catData)

      const tr = s.top_rules || []
      if (topRulesRef.value && tr.length) {
        const c = echarts.init(topRulesRef.value)
        c.setOption({
          tooltip: {},
          xAxis: { type: 'category', data: tr.map(r => r.name), axisLabel: { rotate: 30, fontSize: 11 } },
          yAxis: { type: 'value' },
          series: [{ type: 'bar', data: tr.map(r => r.count), itemStyle: { color: '#1890ff' } }],
          grid: { left: 40, right: 20, bottom: 60, top: 20 },
        })
      }

      const rs = s.recent_scores || []
      if (trendRef.value && rs.length) {
        const c = echarts.init(trendRef.value)
        c.setOption({
          tooltip: { trigger: 'axis' },
          xAxis: { type: 'category', data: rs.map(r => r.id), name: '记录ID' },
          yAxis: { type: 'value', max: 100, name: '风险分数' },
          series: [{
            type: 'line', data: rs.map(r => r.risk_score), smooth: true,
            areaStyle: { opacity: 0.15 }, lineStyle: { color: '#1890ff' },
            itemStyle: { color: '#1890ff' },
          }],
          grid: { left: 50, right: 20, bottom: 30, top: 20 },
        })
      }
    }

    function renderPie(refVal, data, colorList) {
      if (!refVal.value) return
      const c = echarts.init(refVal.value)
      c.setOption({
        tooltip: { trigger: 'item' },
        series: [{
          type: 'pie', radius: ['40%', '70%'], data,
          emphasis: { itemStyle: { shadowBlur: 10, shadowOffsetX: 0, shadowColor: 'rgba(0,0,0,0.2)' } },
          label: { fontSize: 11 },
          itemStyle: colorList ? {
            color: (params) => colorList[params.dataIndex] || undefined
          } : {},
        }]
      })
    }

    onMounted(loadStats)

    return { stats, riskLevelRef, policyRef, categoryRef, topRulesRef, trendRef }
  }
}
</script>

<style scoped>
.stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.card h3 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.card.full { grid-column: 1 / -1; }
.big-number { font-size: 48px; font-weight: 700; color: #1890ff; text-align: center; padding: 20px 0; }
.chart-box { width: 100%; height: 300px; }
</style>
