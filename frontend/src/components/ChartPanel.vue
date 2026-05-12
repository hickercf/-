<template>
  <div class="chart-card">
    <h3>{{ title }}</h3>
    <div ref="chartRef" class="chart-box"></div>
  </div>
</template>

<script>
import { ref, onMounted, watch, nextTick } from 'vue'
import * as echarts from 'echarts'

export default {
  name: 'ChartPanel',
  props: {
    title: { type: String, default: '' },
    option: { type: Object, default: () => ({}) }
  },
  setup(props) {
    const chartRef = ref(null)
    let chartInstance = null

    function render() {
      if (!chartRef.value || !props.option || Object.keys(props.option).length === 0) return
      if (chartInstance) {
        chartInstance.clear()
        chartInstance.dispose()
        chartInstance = null
      }
      chartRef.value.removeAttribute('_echarts_instance_')
      chartInstance = echarts.init(chartRef.value)
      chartInstance.setOption(props.option)
    }

    onMounted(() => { nextTick(render) })
    watch(() => props.option, () => { nextTick(render) }, { deep: true })

    return { chartRef }
  }
}
</script>

<style scoped>
.chart-card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.chart-card h3 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.chart-box { width: 100%; height: 300px; }
</style>
