<template>
  <div class="app">
    <header class="header">
      <div class="header-left">
        <h1 class="logo">AgentGuard</h1>
        <span class="subtitle">AI Agent 零信任安全审计平台</span>
      </div>
      <nav class="nav">
        <button
          v-for="tab in tabs"
          :key="tab.key"
          :class="['nav-btn', { active: activeTab === tab.key }]"
          @click="activeTab = tab.key"
        >{{ tab.label }}</button>
      </nav>
    </header>
    <main class="main">
      <AnalyzePage v-if="activeTab === 'analyze'" />
      <HistoryPage v-if="activeTab === 'history'" />
      <StatsPage v-if="activeTab === 'stats'" />
      <ReportPage v-if="activeTab === 'report'" />
      <EvalPage v-if="activeTab === 'eval'" />
    </main>
  </div>
</template>

<script>
import { ref } from 'vue'
import AnalyzePage from './pages/Analyze.vue'
import HistoryPage from './pages/History.vue'
import StatsPage from './pages/Stats.vue'
import ReportPage from './pages/Report.vue'
import EvalPage from './pages/Evaluation.vue'

export default {
  name: 'App',
  components: { AnalyzePage, HistoryPage, StatsPage, ReportPage, EvalPage },
  setup() {
    const activeTab = ref('analyze')
    const tabs = [
      { key: 'analyze', label: '审计台' },
      { key: 'history', label: '历史记录' },
      { key: 'stats', label: '统计图表' },
      { key: 'report', label: '可信报告' },
      { key: 'eval', label: '评测结果' },
    ]
    return { activeTab, tabs }
  }
}
</script>

<style scoped>
.app { min-height: 100vh; display: flex; flex-direction: column; }
.header {
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
  color: white; padding: 0 24px; display: flex; align-items: center;
  justify-content: space-between; height: 60px; box-shadow: 0 2px 8px rgba(0,0,0,0.15);
}
.header-left { display: flex; align-items: baseline; gap: 12px; }
.logo { font-size: 22px; font-weight: 700; letter-spacing: 1px; }
.subtitle { font-size: 13px; opacity: 0.7; }
.nav { display: flex; gap: 4px; }
.nav-btn {
  background: transparent; color: rgba(255,255,255,0.7); border: none;
  padding: 8px 18px; cursor: pointer; font-size: 14px; border-radius: 4px;
  transition: all 0.2s;
}
.nav-btn:hover { color: white; background: rgba(255,255,255,0.1); }
.nav-btn.active { color: white; background: rgba(255,255,255,0.2); font-weight: 600; }
.main { flex: 1; padding: 20px; max-width: 1400px; margin: 0 auto; width: 100%; }
</style>
