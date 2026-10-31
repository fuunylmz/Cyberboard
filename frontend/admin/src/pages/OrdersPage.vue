<script setup lang="ts">
import { onMounted, ref } from 'vue'
import type { AdminOrderSummary } from '@cyberboard/types'
import StatePanel from '@cyberboard/ui/components/StatePanel.vue'
import StatusBadge from '@cyberboard/ui/components/StatusBadge.vue'
import { adminApi, getApiErrorMessage, normalizePage } from '../api'

const orders = ref<AdminOrderSummary[]>([])
const loading = ref(true)
const error = ref('')
const actionId = ref<string | null>(null)
const actionError = ref('')
const page = ref(1)
const pageSize = 20
const total = ref(0)
const status = ref('all')
const search = ref('')

const money = (cents: number, currency: string) => `${(cents / 100).toFixed(2)} ${currency}`
const key = () => globalThis.crypto?.randomUUID?.() ?? `cb-admin-order-${Date.now()}-${Math.random().toString(36).slice(2)}`

async function load() {
  loading.value = true
  error.value = ''
  try {
    const result = normalizePage(await adminApi.listOrders({ page: page.value, pageSize, search: search.value || undefined, status: status.value === 'all' ? undefined : status.value }), page.value, pageSize)
    orders.value = result.items
    total.value = result.total
  } catch (cause) {
    orders.value = []
    total.value = 0
    error.value = getApiErrorMessage(cause)
  } finally { loading.value = false }
}

async function act(order: AdminOrderSummary, operation: 'paid' | 'refund') {
  const label = operation === 'paid' ? '标记为已支付' : '退款并撤销订阅'
  if (!window.confirm(`确认${label}？订单 ${order.id}`)) return
  actionId.value = order.id
  actionError.value = ''
  try {
    if (operation === 'paid') await adminApi.markOrderPaid(order.id, key())
    else await adminApi.refundOrder(order.id, key())
    await load()
  } catch (cause) { actionError.value = getApiErrorMessage(cause) } finally { actionId.value = null }
}

function query() { page.value = 1; void load() }
onMounted(load)
</script>

<template>
  <div class="page-heading"><div><p class="eyebrow">支付与账单</p><h1>订单</h1><p>查看订单状态，并记录人工支付或退款操作。</p></div><button class="button button--secondary" type="button" :disabled="loading" @click="load">{{ loading ? '加载中…' : '刷新' }}</button></div>
  <p v-if="actionError" class="form-error" role="alert">{{ actionError }}</p>
  <section class="panel">
    <div class="toolbar"><input v-model="search" class="search-input" placeholder="搜索订单、邮箱或套餐" @keyup.enter="query" /><select v-model="status" aria-label="订单状态" @change="query"><option value="all">全部状态</option><option value="pending">待支付</option><option value="paid">已支付</option><option value="refunded">已退款</option><option value="cancelled">已取消</option><option value="failed">失败</option></select><button class="button button--secondary" type="button" :disabled="loading" @click="query">查询</button></div>
    <StatePanel v-if="loading" title="正在加载订单" description="正在读取服务端订单和支付状态。" />
    <StatePanel v-else-if="error" title="订单加载失败" :description="error" action-label="重试" @action="load" />
    <StatePanel v-else-if="!orders.length" title="暂无订单" description="当前筛选条件没有订单记录。" action-label="刷新" @action="load" />
    <div v-else class="table-wrap"><table><thead><tr><th>订单</th><th>用户</th><th>套餐</th><th>金额</th><th>状态</th><th>创建时间</th><th>支付时间</th><th>操作</th></tr></thead><tbody><tr v-for="order in orders" :key="order.id"><td class="mono">{{ order.id }}</td><td><strong>{{ order.userEmail }}</strong><small class="mono">{{ order.userId }}</small></td><td>{{ order.plan }}</td><td>{{ money(order.amountCents, order.currency) }}</td><td><StatusBadge :status="order.status" /></td><td>{{ order.createdAt }}</td><td>{{ order.paidAt ?? '—' }}</td><td><button v-if="order.status === 'pending'" class="row-action" type="button" :disabled="actionId === order.id" @click="act(order, 'paid')">{{ actionId === order.id ? '处理中…' : '标记支付' }}</button><button v-if="order.status === 'paid'" class="row-action row-action--danger" type="button" :disabled="actionId === order.id" @click="act(order, 'refund')">{{ actionId === order.id ? '处理中…' : '退款' }}</button><span v-if="order.status !== 'pending' && order.status !== 'paid'" class="muted">无可用操作</span></td></tr></tbody></table><div class="pagination"><button class="button button--secondary" :disabled="page <= 1 || loading" @click="page--; load()">上一页</button><span>第 {{ page }} 页 · 共 {{ total }} 条</span><button class="button button--secondary" :disabled="page * pageSize >= total || loading" @click="page++; load()">下一页</button></div></div>
  </section>
</template>
