<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import type { DashboardSummary, NodeSummary, UserSummary } from '@cyberboard/types'
import StatusBadge from '@cyberboard/ui/components/StatusBadge.vue'
import StatePanel from '@cyberboard/ui/components/StatePanel.vue'
import { adminApi, getApiErrorMessage, normalizePage } from '../api'

const loading = ref(true)
const error = ref('')
const dashboard = ref<DashboardSummary | null>(null)
const nodes = ref<NodeSummary[]>([])
const users = ref<UserSummary[]>([])
const activeNodes = computed(() => nodes.value.filter((node) => node.status === 'online'))
const formatBytes = (bytes: number) => `${(bytes / 1e12).toFixed(1)} TB`

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [summary, nodeList, userList] = await Promise.all([adminApi.getDashboard(), adminApi.listNodes(), adminApi.listUsers()])
    dashboard.value = summary
    nodes.value = normalizePage(nodeList).items
    users.value = normalizePage(userList).items
  } catch (cause) {
    dashboard.value = null
    nodes.value = []
    users.value = []
    error.value = getApiErrorMessage(cause)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page-heading"><div><p class="eyebrow">系统概览</p><h1>运营总览</h1><p>查看控制面与节点运行状态。</p></div><button class="button button--secondary" type="button" :disabled="loading" @click="load">{{ loading ? '加载中…' : '刷新数据' }}</button></div>
  <StatePanel v-if="loading" title="正在加载运营数据" description="正在从控制面读取总览、节点和用户信息。" />
  <StatePanel v-else-if="error" title="运营数据加载失败" :description="error" action-label="重试" @action="load" />
  <StatePanel v-else-if="!dashboard" title="暂无运营数据" description="控制面尚未返回总览数据。" action-label="重新加载" @action="load" />
  <template v-else>
    <section class="metric-grid"><article class="metric-card"><span>用户总数</span><strong>{{ dashboard.users.toLocaleString() }}</strong><small>服务端统计</small></article><article class="metric-card"><span>生效订阅</span><strong>{{ dashboard.activeSubscriptions.toLocaleString() }}</strong><small>服务端统计</small></article><article class="metric-card"><span>在线节点</span><strong>{{ dashboard.onlineNodes }}</strong><small>{{ activeNodes.length }} 个节点返回在线状态</small></article><article class="metric-card"><span>24 小时流量</span><strong>{{ formatBytes(dashboard.trafficBytes24h) }}</strong><small class="metric-card__warning">{{ dashboard.failedTasks }} 个任务需要处理</small></article></section>
    <section class="content-grid"><div class="panel"><div class="panel-heading"><div><h2>节点状态</h2><p>最近一次心跳与当前配置版本</p></div><RouterLink class="text-link" to="/admin/nodes">查看全部 →</RouterLink></div><StatePanel v-if="!nodes.length" title="暂无节点数据" description="控制面尚未返回可展示的节点。" /><div v-else class="table-wrap"><table><thead><tr><th>节点</th><th>状态</th><th>核心</th><th>延迟</th><th>配置版本</th></tr></thead><tbody><tr v-for="node in nodes" :key="node.id"><td><strong>{{ node.name }}</strong><small>{{ node.region }} · {{ node.address }}</small></td><td><StatusBadge :status="node.status" /></td><td>{{ node.core }} <small>{{ node.coreVersion }}</small></td><td>{{ node.latencyMs ? `${node.latencyMs} ms` : '—' }}</td><td class="mono">{{ node.currentConfigRevision }}</td></tr></tbody></table></div></div><div class="panel"><div class="panel-heading"><div><h2>最近用户</h2><p>订阅与额度概览</p></div><RouterLink class="text-link" to="/admin/users">管理用户 →</RouterLink></div><StatePanel v-if="!users.length" title="暂无用户数据" description="控制面尚未返回可展示的用户。" /><div v-else class="user-list"><div v-for="user in users" :key="user.id" class="user-row"><span class="avatar">{{ user.displayName.slice(0, 1) }}</span><span class="user-main"><strong>{{ user.displayName }}</strong><small>{{ user.email }}</small></span><span class="user-plan">{{ user.plan }}</span></div></div></div></section>
  </template>
</template>
