<template>
  <div class="evidence-card card">
    <h3>可信存证</h3>
    <div class="hash-row"><span class="hash-label">记录哈希：</span><code>{{ recordHash }}</code></div>
    <div v-if="previousHash" class="hash-row"><span class="hash-label">上一条哈希：</span><code>{{ previousHash }}</code></div>
    <div class="hash-row"><span class="hash-label">追踪编号：</span><code>{{ traceId }}</code></div>
    <div v-if="evidenceChainValid !== null" class="status-row">
      审计链状态：<span :class="['status', evidenceChainValid ? 'valid' : 'invalid']">{{ evidenceChainValid ? '完整' : '异常' }}</span>
    </div>
  </div>
</template>

<script>
export default {
  name: 'EvidenceChain',
  props: {
    recordHash: { type: String, default: '' },
    previousHash: { type: String, default: '' },
    traceId: { type: String, default: '' },
    evidenceChainValid: { type: Boolean, default: null }
  }
}
</script>

<style scoped>
.card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.card h3 { font-size: 15px; color: #333; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #f0f0f0; }
.hash-row { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 13px; }
.hash-label { color: #666; white-space: nowrap; }
code { background: #f5f5f5; padding: 2px 8px; border-radius: 3px; font-size: 12px; word-break: break-all; }
.status-row { font-size: 13px; margin-top: 8px; }
.status { padding: 2px 8px; border-radius: 3px; font-weight: 600; }
.status.valid { background: #f6ffed; color: #52c41a; }
.status.invalid { background: #fff1f0; color: #f5222d; }
</style>
