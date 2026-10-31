<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import type { NodeSummary } from '@cyberboard/types'
import StatusBadge from '@cyberboard/ui/components/StatusBadge.vue'
import StatePanel from '@cyberboard/ui/components/StatePanel.vue'
import { adminApi, getApiErrorMessage } from '../api'

const query = ref('')
const statusFilter = ref('all')
const loading = ref(true)
const error = ref('')
const nodes = ref<NodeSummary[]>([])
const filtered = computed(() => nodes.value.filter((node) => {
  const matchesQuery = `${node.name} ${node.region} ${node.address}`.toLowerCase().includes(query.value.toLowerCase())
  return matchesQuery && (statusFilter.value === 'all' || node.status === statusFilter.value)
}))

async function load() {
  loading.value = true
  error.value = ''
  try { nodes.value = await adminApi.listNodes() } catch (cause) { nodes.value = []; error.value = getApiErrorMessage(cause) } finally { loading.value = false }
}
onMounted(load)
</script>

<template>
  <div class="page-heading"><div><p class="eyebrow">基础设施</p><h1>节点</h1><p>管理节点连接、内核版本和配置发布状态。</p></div><button class="primary-button" type="button">+ 注册节点</button></div>
  <section class="panel"><div class="toolbar"><input v-model="query" class="search-input" placeholder="搜索名称、地域或地址" /><select v-model="statusFilter" aria-label="节点状态"><option value="all">全部状态</option><option value="online">在线</option><option value="maintenance">维护</option><option value="offline">离线</option><option value="error">异常</option></select><button class="button button--secondary" type="button" :disabled="loading" @click="load">{{ loading ? '加载中…' : '刷新' }}</button></div><StatePanel v-if="loading" title="正在加载节点" description="正在读取节点心跳和配置版本。" /><StatePanel v-else-if="error" title="节点加载失败" :description="error" action-label="重试" @action="load" /><StatePanel v-else-if="!nodes.length" title="暂无节点" description="控制面尚未注册任何节点。" action-label="刷新" @action="load" /><StatePanel v-else-if="!filtered.length" title="没有匹配的节点" description="尝试调整搜索或状态筛选条件。" action-label="清除筛选" @action="query=''; statusFilter='all'" /><div v-else class="table-wrap"><table><thead><tr><th>节点</th><th>状态</th><th>内核</th><th>Agent</th><th>心跳</th><th>配置</th><th></th></tr></thead><tbody><tr v-for="node in filtered" :key="node.id"><td><strong>{{ node.name }}</strong><small>{{ node.region }} · {{ node.address }}</small></td><td><StatusBadge :status="node.status" /></td><td>{{ node.core }}<small>{{ node.coreVersion }}</small></td><td class="mono">{{ node.agentVersion }}</td><td>{{ node.lastHeartbeatAt ? new Date(node.lastHeartbeatAt).toLocaleString() : '—' }}</td><td class="mono">{{ node.currentConfigRevision }}</td><td><button class="row-action" type="button">详情</button></td></tr></tbody></table></div></section>
</template>
