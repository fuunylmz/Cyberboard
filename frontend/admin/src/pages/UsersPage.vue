<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import type { UserSummary } from '@cyberboard/types'
import StatusBadge from '@cyberboard/ui/components/StatusBadge.vue'
import StatePanel from '@cyberboard/ui/components/StatePanel.vue'
import { adminApi, getApiErrorMessage } from '../api'

const query = ref('')
const statusFilter = ref('all')
const loading = ref(true)
const error = ref('')
const users = ref<UserSummary[]>([])
const filtered = computed(() => users.value.filter((user) => {
  const matchesQuery = `${user.email} ${user.displayName}`.toLowerCase().includes(query.value.toLowerCase())
  return matchesQuery && (statusFilter.value === 'all' || user.status === statusFilter.value)
}))
const formatTraffic = (used: number, quota: number) => `${(used / 1e9).toFixed(0)} / ${(quota / 1e9).toFixed(0)} GB`

async function load() {
  loading.value = true
  error.value = ''
  try { users.value = await adminApi.listUsers() } catch (cause) { users.value = []; error.value = getApiErrorMessage(cause) } finally { loading.value = false }
}
onMounted(load)
</script>

<template>
  <div class="page-heading"><div><p class="eyebrow">账户与权限</p><h1>用户</h1><p>查看账户状态、套餐和流量额度。</p></div><button class="primary-button" type="button">+ 创建用户</button></div>
  <section class="panel"><div class="toolbar"><input v-model="query" class="search-input" placeholder="搜索邮箱或用户名" /><select v-model="statusFilter" aria-label="用户状态"><option value="all">全部状态</option><option value="active">正常</option><option value="suspended">暂停</option><option value="banned">封禁</option></select><button class="button button--secondary" type="button" :disabled="loading" @click="load">{{ loading ? '加载中…' : '刷新' }}</button></div><StatePanel v-if="loading" title="正在加载用户" description="正在读取账户状态和套餐额度。" /><StatePanel v-else-if="error" title="用户加载失败" :description="error" action-label="重试" @action="load" /><StatePanel v-else-if="!users.length" title="暂无用户" description="控制面尚未创建任何用户。" action-label="刷新" @action="load" /><StatePanel v-else-if="!filtered.length" title="没有匹配的用户" description="尝试调整搜索或状态筛选条件。" action-label="清除筛选" @action="query=''; statusFilter='all'" /><div v-else class="table-wrap"><table><thead><tr><th>用户</th><th>状态</th><th>套餐</th><th>流量</th><th>到期时间</th><th>最近活动</th><th></th></tr></thead><tbody><tr v-for="user in filtered" :key="user.id"><td><strong>{{ user.displayName }}</strong><small>{{ user.email }}</small></td><td><StatusBadge :status="user.status" /></td><td>{{ user.plan }}</td><td class="mono">{{ formatTraffic(user.usedBytes, user.quotaBytes) }}</td><td>{{ user.expiresAt }}</td><td>{{ user.lastSeenAt ? new Date(user.lastSeenAt).toLocaleString() : '—' }}</td><td><button class="row-action" type="button">详情</button></td></tr></tbody></table></div></section>
</template>
