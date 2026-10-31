<script setup lang="ts">
import { onMounted, ref } from 'vue'
import type { AuditLogSummary } from '@cyberboard/types'
import StatePanel from '@cyberboard/ui/components/StatePanel.vue'
import { auditApi, getApiErrorMessage, normalizePage } from '../api'

const logs = ref<AuditLogSummary[]>([])
const loading = ref(true)
const error = ref('')
const search = ref('')
const action = ref('')
const page = ref(1)
const total = ref(0)
const pageSize = 20
const selected = ref<AuditLogSummary | null>(null)

async function load() {
  loading.value = true; error.value = ''
  try { const result = normalizePage(await auditApi.list({ page: page.value, pageSize, search: search.value || undefined, action: action.value || undefined }), page.value, pageSize); logs.value = result.items; total.value = result.total }
  catch (cause) { logs.value = []; total.value = 0; error.value = getApiErrorMessage(cause) }
  finally { loading.value = false }
}
function query() { page.value = 1; void load() }
onMounted(load)
</script>

<template>
  <div class="page-heading"><div><p class="eyebrow">安全与追踪</p><h1>审计日志</h1><p>查看租户内的管理操作、资源变更和令牌事件。</p></div><button class="button button--secondary" type="button" :disabled="loading" @click="load">{{ loading ? '加载中…' : '刷新' }}</button></div>
  <section class="panel"><div class="toolbar"><input v-model="search" class="search-input" placeholder="搜索动作或资源类型" @keyup.enter="query" /><input v-model="action" class="search-input" placeholder="精确动作（可选）" @keyup.enter="query" /><button class="button button--secondary" type="button" :disabled="loading" @click="query">查询</button></div><StatePanel v-if="loading" title="正在加载审计日志" description="正在读取租户审计记录。"/><StatePanel v-else-if="error" title="审计日志加载失败" :description="error" action-label="重试" @action="load"/><StatePanel v-else-if="!logs.length" title="暂无审计记录" description="当前筛选条件没有匹配的操作。"/><div v-else class="table-wrap"><table><thead><tr><th>时间</th><th>动作</th><th>资源</th><th>操作人</th><th>请求 ID</th><th>详情</th></tr></thead><tbody><tr v-for="log in logs" :key="log.id"><td>{{ log.createdAt }}</td><td class="mono">{{ log.action }}</td><td>{{ log.resourceType }}<small v-if="log.resourceId" class="mono">{{ log.resourceId }}</small></td><td>{{ log.actorEmail || log.actorUserId || '系统' }}</td><td class="mono">{{ log.requestId || '—' }}</td><td><button class="row-action" type="button" @click="selected = log">查看 JSON</button></td></tr></tbody></table><div class="pagination"><button class="button button--secondary" :disabled="page <= 1 || loading" @click="page--; load()">上一页</button><span>第 {{ page }} 页 · 共 {{ total }} 条</span><button class="button button--secondary" :disabled="page * pageSize >= total || loading" @click="page++; load()">下一页</button></div></div></section>
  <div v-if="selected" class="modal-backdrop" @click.self="selected = null"><section class="modal-panel"><div class="panel-heading"><h2>审计详情</h2><button class="button button--secondary" type="button" @click="selected = null">关闭</button></div><pre class="audit-json">{{ JSON.stringify(selected.details, null, 2) }}</pre></section></div>
</template>

<style scoped>
.modal-backdrop { position: fixed; inset: 0; z-index: 20; display: grid; place-items: center; padding: 24px; background: rgb(15 23 42 / 45%); }
.modal-panel { width: min(720px, 100%); max-height: 80vh; overflow: auto; padding: 22px; background: var(--cb-surface); border: 1px solid var(--cb-border); border-radius: 8px; box-shadow: 0 18px 50px rgb(15 23 42 / 20%); }
.audit-json { margin: 0; padding: 14px; overflow: auto; background: var(--cb-surface-muted); border-radius: 6px; font: 12px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; }
</style>
