<template>
  <div class="target-page">
    <div class="page-header">
      <h2>靶标 Agent 管理</h2>
      <button class="btn-primary" @click="showForm = true">+ 注册新靶标</button>
    </div>

    <!-- 注册/编辑表单 -->
    <div v-if="showForm" class="modal-overlay" @click.self="closeForm">
      <div class="modal">
        <h3>{{ editingTarget ? '编辑靶标' : '注册新靶标 Agent' }}</h3>
        <div class="form-group">
          <label for="target-name">Agent 名称 *</label>
          <input id="target-name" v-model="form.name" placeholder="例如：智能客服 Agent" />
        </div>
        <div class="form-group">
          <label for="target-system-prompt">System Prompt</label>
          <textarea id="target-system-prompt" v-model="form.system_prompt" rows="6" placeholder="输入 Agent 的 System Prompt..."></textarea>
        </div>
        <div class="form-group">
          <label>API 工具列表</label>
          <div v-for="(api, i) in form.api_schemas" :key="i" class="api-row">
            <input v-model="api.name" placeholder="API 名称" class="api-name" />
            <input v-model="api.description" placeholder="描述" class="api-desc" />
            <button class="btn-sm btn-danger" @click="form.api_schemas.splice(i, 1)">删除</button>
          </div>
          <button class="btn-sm" @click="form.api_schemas.push({name:'',description:'',parameters:[],permissions:[]})">+ 添加 API</button>
        </div>
        <div class="form-group">
          <label>安全约束声明</label>
          <div v-for="(c, i) in form.safety_constraints" :key="i" class="constraint-row">
            <input v-model="form.safety_constraints[i]" placeholder="例如：不得泄露用户个人信息" />
            <button class="btn-sm btn-danger" @click="form.safety_constraints.splice(i, 1)">×</button>
          </div>
          <button class="btn-sm" @click="form.safety_constraints.push('')">+ 添加约束</button>
        </div>
        <div class="form-group">
          <label for="target-access-mode">接入模式</label>
          <select id="target-access-mode" v-model="form.access_mode">
            <option value="callback">HTTP Callback（推荐）</option>
            <option value="log">日志接入（离线模式）</option>
            <option value="sandbox">直接沙箱</option>
          </select>
        </div>
        <div v-if="form.access_mode === 'callback'" class="form-group">
          <label for="target-callback-url">Callback URL</label>
          <input id="target-callback-url" v-model="form.access_config.callback_url" placeholder="https://your-agent.com/agentfuzzer/callback" />
        </div>
        <div v-if="form.access_mode === 'log'" class="form-group">
          <label for="target-log-file">日志文件路径</label>
          <input id="target-log-file" v-model="form.access_config.log_file" placeholder="/var/log/agent.log" />
        </div>
        <div class="modal-actions">
          <button class="btn-secondary" @click="closeForm">取消</button>
          <button class="btn-primary" @click="submitTarget" :disabled="!form.name">{{ editingTarget ? '保存' : '提交注册' }}</button>
        </div>
      </div>
    </div>

    <!-- 靶标列表 -->
    <div v-if="loading" class="loading">加载中...</div>
    <div v-else-if="!targets.length" class="empty">
      <p>暂无靶标 Agent，点击上方按钮注册第一个</p>
    </div>
    <div v-else class="target-grid">
      <div v-for="t in targets" :key="t.target_id" class="target-card">
        <div class="card-header">
          <h4>{{ t.name }}</h4>
          <span :class="['mode-badge', t.access_mode]">{{ modeLabel(t.access_mode) }}</span>
        </div>
        <div class="card-body">
          <div class="info-row">
            <span class="label">API 数量</span>
            <span class="value">{{ (t.api_schemas || []).length }}</span>
          </div>
          <div class="info-row">
            <span class="label">安全约束</span>
            <span class="value">{{ (t.safety_constraints || []).length }} 条</span>
          </div>
          <div class="info-row">
            <span class="label">创建时间</span>
            <span class="value">{{ t.created_at }}</span>
          </div>
          <div v-if="t.attack_surface" class="exposure-badge" :class="t.attack_surface.overall_exposure">
            暴露等级: {{ t.attack_surface.overall_exposure }}
          </div>
        </div>
        <div class="card-actions">
          <button class="btn-sm btn-primary" @click="startScan(t)" :disabled="scanningTarget === t.target_id">
            {{ scanningTarget === t.target_id ? '启动中...' : '开始扫描' }}
          </button>
          <button class="btn-sm" @click="viewDetail(t)">详情</button>
          <button class="btn-sm" @click="editTarget(t)">编辑</button>
          <button class="btn-sm btn-danger" @click="removeTarget(t)">删除</button>
        </div>
      </div>
    </div>

    <!-- 靶标详情弹窗 -->
    <div v-if="detailTarget" class="modal-overlay" @click.self="detailTarget = null">
      <div class="modal detail-modal">
        <h3>{{ detailTarget.name }} — 攻击面分析</h3>
        <div v-if="detailTarget.attack_surface">
          <div class="section">
            <h4>可绕过约束 ({{ detailTarget.attack_surface.constraints_to_bypass?.length || 0 }})</h4>
            <ul>
              <li v-for="c in detailTarget.attack_surface.constraints_to_bypass" :key="c">{{ c }}</li>
            </ul>
          </div>
          <div class="section">
            <h4>高价值 API ({{ detailTarget.attack_surface.high_value_apis?.length || 0 }})</h4>
            <div class="tags">
              <span v-for="a in detailTarget.attack_surface.high_value_apis" :key="a" class="tag tag-danger">{{ a }}</span>
            </div>
          </div>
          <div class="section">
            <h4>敏感参数 ({{ detailTarget.attack_surface.sensitive_params?.length || 0 }})</h4>
            <div class="tags">
              <span v-for="p in detailTarget.attack_surface.sensitive_params" :key="p" class="tag tag-warning">{{ p }}</span>
            </div>
          </div>
          <div class="section">
            <h4>弱 Prompt 模式</h4>
            <ul>
              <li v-for="w in detailTarget.attack_surface.weak_prompt_patterns" :key="w">{{ w }}</li>
            </ul>
          </div>
          <div class="section">
            <h4>综合暴露等级: <span :class="'exposure-text ' + detailTarget.attack_surface.overall_exposure">{{ detailTarget.attack_surface.overall_exposure.toUpperCase() }}</span></h4>
          </div>
        </div>
        <button class="btn-secondary" @click="detailTarget = null">关闭</button>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, reactive, onMounted } from 'vue'
import { getTargets, getTargetDetail, createTarget, updateTarget, deleteTarget, startTargetScan } from '../api/request.js'

export default {
  name: 'TargetPage',
  setup() {
    const targets = ref([])
    const loading = ref(false)
    const showForm = ref(false)
    const editingTarget = ref(null)
    const detailTarget = ref(null)
    const scanningTarget = ref(null)

    const form = reactive({
      name: '',
      system_prompt: '',
      api_schemas: [],
      safety_constraints: [],
      access_mode: 'callback',
      access_config: {},
    })

    const loadTargets = async () => {
      loading.value = true
      try {
        const data = await getTargets()
        targets.value = data.targets || []
      } catch (e) {
        console.error(e)
      } finally {
        loading.value = false
      }
    }

    const closeForm = () => {
      showForm.value = false
      editingTarget.value = null
      Object.assign(form, {
        name: '', system_prompt: '', api_schemas: [],
        safety_constraints: [], access_mode: 'callback', access_config: {},
      })
    }

    const submitTarget = async () => {
      try {
        if (editingTarget.value) {
          await updateTarget(editingTarget.value.target_id, { ...form })
        } else {
          await createTarget({ ...form })
        }
        closeForm()
        await loadTargets()
      } catch (e) {
        alert('保存靶标失败: ' + (e.response?.data?.detail || e.message))
      }
    }

    const editTarget = (t) => {
      editingTarget.value = t
      Object.assign(form, {
        name: t.name,
        system_prompt: t.system_prompt || '',
        api_schemas: t.api_schemas ? [...t.api_schemas] : [],
        safety_constraints: t.safety_constraints ? [...t.safety_constraints] : [],
        access_mode: t.access_mode || 'callback',
        access_config: t.access_config ? { ...t.access_config } : {},
      })
      showForm.value = true
    }

    const viewDetail = async (t) => {
      try {
        const data = await getTargetDetail(t.target_id)
        detailTarget.value = data.target
        detailTarget.value.attack_surface = data.attack_surface
      } catch (e) {
        alert('加载靶标详情失败: ' + (e.response?.data?.detail || e.message))
      }
    }

    const removeTarget = async (t) => {
      if (!confirm(`确定删除靶标 "${t.name}"？`)) return
      try {
        await deleteTarget(t.target_id)
        await loadTargets()
      } catch (e) {
        alert('删除靶标失败: ' + (e.response?.data?.detail || e.message))
      }
    }

    const startScan = async (t) => {
      scanningTarget.value = t.target_id
      try {
        const result = await startTargetScan(t.target_id, { scan_mode: 'standard' })
        alert(`扫描已启动！扫描ID: ${result.scan_id}`)
      } catch (e) {
        alert('启动扫描失败: ' + (e.response?.data?.detail || e.message))
      } finally {
        scanningTarget.value = null
      }
    }

    const modeLabel = (m) => ({ callback: 'HTTP回调', log: '日志模式', sandbox: '沙箱' }[m] || m)

    onMounted(loadTargets)

    return {
      targets, loading, showForm, editingTarget, detailTarget, scanningTarget,
      form, closeForm, submitTarget, editTarget, viewDetail, removeTarget, startScan, modeLabel,
    }
  }
}
</script>

<style scoped>
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.target-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 16px; }
.target-card {
  background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.08);
  overflow: hidden; transition: box-shadow 0.2s;
}
.target-card:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.12); }
.card-header { display: flex; justify-content: space-between; align-items: center; padding: 14px 16px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; }
.card-header h4 { margin: 0; font-size: 15px; }
.card-body { padding: 14px 16px; }
.info-row { display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px; }
.info-row .label { color: #64748b; }
.info-row .value { color: #1e293b; font-weight: 500; }
.card-actions { padding: 10px 16px; border-top: 1px solid #e2e8f0; display: flex; gap: 6px; }
.mode-badge { font-size: 11px; padding: 2px 8px; border-radius: 10px; background: #e2e8f0; }
.mode-badge.callback { background: #dbeafe; color: #2563eb; }
.mode-badge.sandbox { background: #fce7f3; color: #db2777; }
.exposure-badge { margin-top: 8px; font-size: 12px; padding: 4px 8px; border-radius: 4px; text-align: center; }
.exposure-badge.critical { background: #fecaca; color: #dc2626; }
.exposure-badge.high { background: #fed7aa; color: #ea580c; }
.exposure-badge.medium { background: #fef08a; color: #ca8a04; }
.exposure-badge.low { background: #d1fae5; color: #059669; }

.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; z-index: 100; }
.modal { background: #fff; border-radius: 12px; padding: 24px; width: 600px; max-height: 85vh; overflow-y: auto; }
.modal h3 { margin: 0 0 16px; }
.detail-modal { width: 700px; }
.form-group { margin-bottom: 14px; }
.form-group label { display: block; margin-bottom: 4px; font-size: 13px; font-weight: 600; color: #475569; }
.form-group input, .form-group textarea, .form-group select { width: 100%; padding: 8px 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; }
.form-group textarea { resize: vertical; font-family: monospace; }
.api-row, .constraint-row { display: flex; gap: 6px; margin-bottom: 6px; }
.api-name { flex: 1; } .api-desc { flex: 2; }
.modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
.section { margin-bottom: 16px; } .section h4 { margin: 0 0 8px; font-size: 14px; }
.tags { display: flex; gap: 6px; flex-wrap: wrap; }
.tag { font-size: 12px; padding: 3px 8px; border-radius: 4px; }
.tag-danger { background: #fee2e2; color: #dc2626; }
.tag-warning { background: #fef3c7; color: #d97706; }
.exposure-text { font-weight: 700; }
.exposure-text.critical { color: #dc2626; }
.exposure-text.high { color: #ea580c; }
.exposure-text.medium { color: #ca8a04; }
.exposure-text.low { color: #059669; }

.btn-primary { background: #2563eb; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
.btn-primary:hover { background: #1d4ed8; }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-secondary { background: #e2e8f0; color: #475569; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
.btn-sm { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; }
.btn-danger { color: #dc2626; border-color: #fecaca; }
.loading, .empty { text-align: center; padding: 60px; color: #94a3b8; }
</style>
