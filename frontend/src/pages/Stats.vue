<template>
  <div class="stats-page">
    <div class="stats-grid">
      <!-- 审计统计 -->
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

      <!-- 扫描统计 (新增) -->
      <div class="card full section-header">
        <h2>扫描统计</h2>
      </div>
      <div class="card">
        <h3>扫描漏洞严重度分布</h3>
        <div ref="scanSevRef" class="chart-box"></div>
      </div>
      <div class="card">
        <h3>防线崩溃分布 (雷达图)</h3>
        <div ref="defenseRadarRef" class="chart-box"></div>
      </div>
      <div class="card full">
        <h3>攻击载荷分类统计</h3>
        <div ref="payloadCatRef" class="chart-box"></div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, nextTick } from 'vue'
import { getStats, getScans, getPayloadCategories } from '../api/request.js'
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
    const scanSevRef = ref(null)
    const defenseRadarRef = ref(null)
    const payloadCatRef = ref(null)

    const colors = ['#52c41a', '#faad14', '#fa8c16', '#f5222d']

    async function loadStats() {
      try {
        stats.value = await getStats()
        await nextTick()
        renderAuditCharts()
        await renderScanCharts()
      } catch (e) { console.error(e) }
    }

    function renderAuditCharts() {
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

    async function renderScanCharts() {
      try {
        const scans = (await getScans(null, 100)).scans || []

        // 漏洞严重度分布
        const sevDist = { critical: 0, high: 0, medium: 0, low: 0 }
        scans.forEach(s => {
          if (s.summary?.severity_distribution) {
            for (const [k, v] of Object.entries(s.summary.severity_distribution)) {
              sevDist[k] = (sevDist[k] || 0) + v
            }
          }
        })
        if (scanSevRef.value) {
          const c = echarts.init(scanSevRef.value)
          c.setOption({
            tooltip: { trigger: 'item' },
            series: [{
              type: 'pie', radius: ['45%', '75%'],
              data: [
                { name: 'Critical', value: sevDist.critical, itemStyle: { color: '#dc2626' } },
                { name: 'High', value: sevDist.high, itemStyle: { color: '#ea580c' } },
                { name: 'Medium', value: sevDist.medium, itemStyle: { color: '#f59e0b' } },
                { name: 'Low', value: sevDist.low, itemStyle: { color: '#8b5cf6' } },
              ],
            }],
          })
        }

        // 防线崩溃雷达图（真实数据统计）
        if (defenseRadarRef.value) {
          const layerCounts = { L1: 0, L2: 0, L3: 0, L4: 0, L5: 0 }
          scans.forEach(s => {
            if (s.summary?.defense_layer_distribution) {
              for (const [k, v] of Object.entries(s.summary.defense_layer_distribution)) {
                layerCounts[k] = (layerCounts[k] || 0) + v
              }
            }
          })
          const maxVal = Math.max(...Object.values(layerCounts), 1)
          const c = echarts.init(defenseRadarRef.value)
          c.setOption({
            tooltip: {},
            radar: {
              indicator: [
                { name: 'L1 Prompt', max: maxVal },
                { name: 'L2 意图', max: maxVal },
                { name: 'L3 权限', max: maxVal },
                { name: 'L4 数据', max: maxVal },
                { name: 'L5 执行', max: maxVal },
              ],
            },
            series: [{
              type: 'radar',
              data: [{
                name: '防线崩溃次数',
                value: [
                  layerCounts.L1 || 0,
                  layerCounts.L2 || 0,
                  layerCounts.L3 || 0,
                  layerCounts.L4 || 0,
                  layerCounts.L5 || 0,
                ],
                areaStyle: { opacity: 0.2 },
                itemStyle: { color: '#dc2626' },
              }],
            }],
          })
        }

        // 载荷分类统计
        try {
          const catData = await getPayloadCategories()
          if (payloadCatRef.value && catData?.categories) {
            const c = echarts.init(payloadCatRef.value)
            c.setOption({
              tooltip: {},
              xAxis: { type: 'category', data: catData.categories.map(x => x.name), axisLabel: { rotate: 30, fontSize: 10 } },
              yAxis: { type: 'value' },
              series: [{
                type: 'bar', data: catData.categories.map(x => x.count),
                itemStyle: {
                  color: (params) => {
                    const palette = ['#dc2626', '#ea580c', '#f59e0b', '#8b5cf6', '#3b82f6', '#06b6d4', '#10b981', '#f97316', '#ec4899', '#6366f1']
                    return palette[params.dataIndex % palette.length]
                  },
                },
              }],
              grid: { left: 50, right: 20, bottom: 80, top: 10 },
            })
          }
        } catch (e) { /* */ }
      } catch (e) { console.error(e) }
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
          itemStyle: colorList ? { color: (params) => colorList[params.dataIndex] || undefined } : {},
        }],
      })
    }

    onMounted(loadStats)

    return {
      stats, riskLevelRef, policyRef, categoryRef, topRulesRef, trendRef,
      scanSevRef, defenseRadarRef, payloadCatRef,
    }
  }
}
</script>

<style scoped>
.stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.card h3 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.card.full { grid-column: 1 / -1; }
.section-header { background: #f8fafc; }
.section-header h2 { margin: 0; font-size: 18px; color: #1e293b; }
.big-number { font-size: 48px; font-weight: 700; color: #1890ff; text-align: center; padding: 20px 0; }
.chart-box { width: 100%; height: 300px; }
</style>
