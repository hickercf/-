<template>
  <div class="graph-card">
    <h3>{{ title }}</h3>
    <div ref="graphRef" class="graph-container"></div>
  </div>
</template>

<script>
import { ref, onMounted, watch, nextTick } from 'vue'
import * as echarts from 'echarts'

export default {
  name: 'BehaviorChainGraph',
  props: {
    title: { type: String, default: '行为链路图' },
    nodes: { type: Array, default: () => [] },
    edges: { type: Array, default: () => [] },
    mode: { type: String, default: 'graph' },  // 'graph' | 'react' | 'timeline'
    reactSteps: { type: Array, default: () => [] },
    breaches: { type: Array, default: () => [] },
  },
  setup(props) {
    const graphRef = ref(null)
    let chartInstance = null

    function getBreachAt(index) {
      if (!props.breaches) return null
      return props.breaches.find(b => b.step_index === index)
    }

    function renderGraph() {
      if (!graphRef.value) return
      if (chartInstance) chartInstance.dispose()
      chartInstance = echarts.init(graphRef.value)

      chartInstance.setOption({
        tooltip: {
          formatter(params) {
            if (params.dataType === 'node' && params.data?.data) {
              const d = params.data.data
              return '<b>' + d.action + '</b><br/>工具: ' + d.tool + '<br/>对象: ' + d.object + '<br/>数据: ' + d.data_type + '<br/>目标: ' + d.destination
            }
          }
        },
        animationDurationUpdate: 300,
        series: [{
          type: 'graph', layout: 'force', roam: true, draggable: true,
          force: { repulsion: 200, edgeLength: 150 },
          data: buildGraphNodes(), links: buildGraphEdges(),
          emphasis: { focus: 'adjacency' },
        }]
      })
    }

    function buildGraphNodes() {
      const scores = { delete: 90, execute: 85, leak: 90, send: 75, upload: 75, download: 65, override: 80, read: 35 }
      return props.nodes.map((n, i) => {
        const s = scores[n.action] || 30
        let color = '#52c41a'
        if (s > 60) color = '#f5222d'
        else if (s > 40) color = '#fa8c16'
        else if (s > 20) color = '#faad14'
        return {
          id: n.id || 'n' + i,
          name: n.action + '\n' + (n.object || n.data_type || ''),
          symbolSize: 60,
          itemStyle: { color },
          label: { show: true, fontSize: 11, color: '#fff' },
          data: n,
        }
      })
    }

    function buildGraphEdges() {
      const graphEdges = props.edges.map(e => ({
        source: e.source, target: e.target,
        lineStyle: { curveness: 0.2, width: 2, color: '#999' },
        label: { show: true, formatter: e.relation, fontSize: 10 },
      }))

      if (props.nodes.length > 1 && props.edges.length === 0) {
        for (let i = 0; i < props.nodes.length - 1; i++) {
          graphEdges.push({
            source: props.nodes[i].id || 'n' + i,
            target: props.nodes[i + 1].id || 'n' + (i + 1),
            lineStyle: { curveness: 0.1, width: 2, color: '#999' },
          })
        }
      }
      return graphEdges
    }

    function renderReActTimeline() {
      if (!graphRef.value) return
      if (chartInstance) chartInstance.dispose()
      chartInstance = echarts.init(graphRef.value)

      const steps = props.reactSteps || []
      if (!steps.length) return

      const categories = [
        { name: 'Thought', itemStyle: { color: '#3b82f6' }, symbol: 'roundRect' },
        { name: 'Action', itemStyle: { color: '#f59e0b' }, symbol: 'triangle' },
        { name: 'Observation', itemStyle: { color: '#10b981' }, symbol: 'circle' },
      ]

      const data = []
      const links = []

      steps.forEach((step, i) => {
        const type = (step.type || (step.thought && 'thought') || (step.action && 'action') || 'observation')
        const catIndex = type === 'thought' ? 0 : type === 'action' ? 1 : 2
        const breach = getBreachAt(step.step_index || i)

        const label = type === 'thought' ? (step.thought || '').substring(0, 20) :
          type === 'action' ? (step.action || '').substring(0, 20) :
          (step.observation || '').substring(0, 20)

        data.push({
          name: `Step ${i + 1}\n${label}...`,
          category: catIndex,
          symbolSize: breach ? 50 : 35,
          itemStyle: breach ? {
            color: '#ef4444',
            borderColor: '#dc2626',
            borderWidth: 3,
            shadowBlur: 10,
            shadowColor: 'rgba(239,68,68,0.5)',
          } : undefined,
          label: { show: true, fontSize: 10 },
          tooltip: {
            formatter: () => {
              let tip = `<b>Step ${i + 1}</b><br/>${type}: ${label}`
              if (breach) tip += `<br/><br/>⚠️ <b>${breach.layer}</b>: ${breach.description}`
              return tip
            },
          },
          data: { step, breach },
        })

        if (i > 0) {
          links.push({ source: i - 1, target: i })
        }
      })

      chartInstance.setOption({
        tooltip: {},
        legend: { data: categories.map(c => c.name), bottom: 0 },
        series: [{
          type: 'graph', layout: 'force', roam: true, draggable: true,
          force: { repulsion: 300, edgeLength: 200, layoutAnimation: true },
          categories, data, links,
          emphasis: { focus: 'adjacency' },
        }],
      })
    }

    function render() {
      if (props.mode === 'react' && props.reactSteps?.length) {
        renderReActTimeline()
      } else {
        renderGraph()
      }
    }

    onMounted(() => { nextTick(render) })
    watch(() => [props.nodes, props.edges, props.reactSteps, props.breaches, props.mode],
      () => { nextTick(render) }, { deep: true })

    return { graphRef }
  },
}
</script>

<style scoped>
.graph-card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.graph-card h3 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.graph-container { width: 100%; height: 350px; }
</style>
