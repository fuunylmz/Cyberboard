<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import type { SubscriptionSummary } from '@cyberboard/types'
import StatusBadge from '@cyberboard/ui/components/StatusBadge.vue'
import StatePanel from '@cyberboard/ui/components/StatePanel.vue'
import { adminApi, getApiErrorMessage } from '../api'

const query = ref('')
const statusFilter = ref('all')
const loading = ref(true)
const error = ref('')
const subscriptions = ref<SubscriptionSummary[]>([])
const filtered = computed(() => subscriptions.value.filter((subscription) => {
  const matchesQuery = `${subscription.id} ${subscription.userEmail}`.toLowerCase().includes(query.value.toLowerCase())
  return matchesQuery && (statusFilter.value === 'all' || subscription.status === statusFilter.value)
}))
const formatTraffic = (used: number, quota: number) => `${(used / 1e9).toFixed(0)} / ${(quota / 1e9).toFixed(0)} GB`

async function load() {
  loading.value = true
  error.value = ''
  try { subscriptions.value = await adminApi.listSubscriptions() } catch (cause) { subscriptions.value = []; error.value = getApiErrorMessage(cause) } finally { loading.value = false }
}
onMounted(load)
</script>

<template>
  <div class="page-heading"><div><p class="eyebrow">访问凭证</p><h1>订阅</h1><p>管理订阅状态、令牌轮换和生效时间。</p></div><button class="primary-button" type="button">+ 新建订阅</button></div>
  <section class="panel"><div class="toolbar"><input v-model="query" class="search-input" placeholder="搜索用户邮箱或订阅 ID" /><select v-model="statusFilter" aria-label="订阅状态"><option value="all">全部状态</option><option value="active">生效</option><option value="pending">待生效</option><option value="expired">过期</option><option value="revoked">撤销</option></select><button class="button button--secondary" type="button" :disabled="loading" @click="load">{{ loading ? '加载中…' : '刷新' }}</button></div><StatePanel v-if="loading" title="正在加载订阅" description="正在读取订阅状态和访问凭证。" /><StatePanel v-else-if="error" title="订阅加载失败" :description="error" action-label="重试" @action="load" /><StatePanel v-else-if="!subscriptions.length" title="暂无订阅" description="控制面尚未创建任何订阅。" action-label="刷新" @action="load" /><StatePanel v-else-if="!filtered.length" title="没有匹配的订阅" description="尝试调整搜索或状态筛选条件。" action-label="清除筛选" @action="query=''; statusFilter='all'" /><div v-else class="table-wrap"><table><thead><tr><th>订阅 ID</th><th>用户</th><th>套餐</th><th>状态</th><th>用量</th><th>到期时间</th><th>令牌</th><th></th></tr></thead><tbody><tr v-for="subscription in filtered" :key="subscription.id"><td class="mono">{{ subscription.id }}</td><td>{{ subscription.userEmail }}</td><td>{{ subscription.plan }}</td><td><StatusBadge :status="subscription.status" /></td><td class="mono">{{ formatTraffic(subscription.trafficUsedBytes, subscription.trafficQuotaBytes) }}</td><td>{{ subscription.expiresAt }}</td><td class="mono">{{ subscription.tokenHint }}</td><td><button class="row-action" type="button">管理</button></td></tr></tbody></table></div></section>
</template>
