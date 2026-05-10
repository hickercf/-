<template>
  <div class="rule-card">
    <h3>命中规则 ({{ rules.length }})</h3>
    <table v-if="rules.length" class="rules-table">
      <thead><tr><th>ID</th><th>规则名称</th><th>类别</th><th>分数</th><th>等级</th></tr></thead>
      <tbody>
        <tr v-for="r in rules" :key="r.id">
          <td>{{ r.id }}</td><td>{{ r.name }}</td><td>{{ r.category }}</td>
          <td>{{ r.score }}</td><td><span :class="'level-tag ' + r.level">{{ r.level }}</span></td>
        </tr>
      </tbody>
    </table>
    <p v-else class="empty-text">未命中安全规则</p>
  </div>
</template>

<script>
export default {
  name: 'RuleList',
  props: {
    rules: { type: Array, default: () => [] }
  }
}
</script>

<style scoped>
.rule-card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.rule-card h3 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.rules-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.rules-table th, .rules-table td { padding: 8px 12px; border: 1px solid #f0f0f0; text-align: left; }
.rules-table th { background: #fafafa; font-weight: 600; }
.level-tag { padding: 2px 8px; border-radius: 3px; font-size: 11px; }
.level-tag.low { background: #f6ffed; color: #52c41a; }
.level-tag.medium { background: #fffbe6; color: #faad14; }
.level-tag.high { background: #fff7e6; color: #fa8c16; }
.level-tag.critical { background: #fff1f0; color: #f5222d; }
.empty-text { color: #999; font-size: 13px; }
</style>
