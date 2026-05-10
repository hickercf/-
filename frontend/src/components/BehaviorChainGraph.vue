<template>
  <div class="graph-card">
    <h3>行为链图谱</h3>
    <div ref="graphRef" class="graph-container"></div>
  </div>
</template>

<script>
import { ref, onMounted, watch, nextTick } from 'vue'
import * as echarts from 'echarts'

export default {
  name: 'BehaviorChainGraph',
  props: {
    nodes: { type: Array, default: () => [] },
    edges: { type: Array, default: () => [] }
  },
  setup(props) {
    const graphRef = ref(null)
    let chartInstance = null

    function renderGraph() {
      if (!graphRef.value) return
      if (chartInstance) chartInstance.dispose()
      chartInstance = echarts.init(graphRef.value)

      const scores = { delete: 90, execute: 85, leak: 90, send: 75, upload: 75, download: 65, override: 80, read: 35 }
      const graphNodes = props.nodes.map((n, i) => {
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
          data: n
        }
      })

      const graphEdges = props.edges.map(e => ({
        source: e.source,
        target: e.target,
        lineStyle: { curveness: 0.2, width: 2, color: '#999' },
        label: { show: true, formatter: e.relation, fontSize: 10 }
      }))

      if (props.nodes.length > 1 && props.edges.length === 0) {
        for (let i = 0; i < props.nodes.length - 1; i++) {
          graphEdges.push({
            source: props.nodes[i].id || 'n' + i,
            target: props.nodes[i + 1].id || 'n' + (i + 1),
            lineStyle: { curveness: 0.1, width: 2, color: '#999' }
          })
        }
      }

      chartInstance.setOption({
        tooltip: {
          formatter(params) {
            if (params.dataType === 'node' && params.data?.data) {
              const d = params.data.data
              return '<b>' + d.action + '</b><br/>工具: ' + d.tool + '<br/>对象: ' + d.object + '<br/>数据: ' + d.data_type + '<br/>目标: ' + d.destination
            }
            return ''
          }
        },
        animationDurationUpdate: 300,
        series: [{
          type: 'graph', layout: 'force', roam: true, draggable: true,
          force: { repulsion: 200, edgeLength: 150 },
          data: graphNodes, links: graphEdges, emphasis: { focus: 'adjacency' }
        }]
      })
    }

    onMounted(() => { nextTick(renderGraph) })
    watch(() => [props.nodes, props.edges], () => { nextTick(renderGraph) }, { deep: true })

    return { graphRef }
  }
}
</script>

<style scoped>
.graph-card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.graph-card h3 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.graph-container { width: 100%; height: 300px; }
</style>
