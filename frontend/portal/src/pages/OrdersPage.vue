<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import type { OrderSummary, PlanSummary } from '@cyberboard/types'
import StatePanel from '@cyberboard/ui/components/StatePanel.vue'
import StatusBadge from '@cyberboard/ui/components/StatusBadge.vue'
import { getApiErrorMessage, normalizeList, portalApi } from '../api'

const loading = ref(true)
const creating = ref(false)
const error = ref('')
const createError = ref('')
const orders = ref<OrderSummary[]>([])
const plans = ref<PlanSummary[]>([])
const plansLoading = ref(true)
const plansError = ref('')
const showCreate = ref(false)
const form = reactive({ planId: '' })
const money = (cents: number, currency: string) => `${(cents / 100).toFixed(2)} ${currency}`

async function load() {
  loading.value = true
  error.value = ''
  try { orders.value = normalizeList(await portalApi.listOrders({ page: 1, pageSize: 20 })) } catch (cause) { orders.value = []; error.value = getApiErrorMessage(cause) } finally { loading.value = false }
}

async function loadPlans() {
  plansLoading.value = true
  plansError.value = ''
  try { plans.value = normalizeList(await portalApi.listPlans()) } catch (cause) { plans.value = []; plansError.value = getApiErrorMessage(cause) } finally { plansLoading.value = false }
}

function newIdempotencyKey() {
  return globalThis.crypto?.randomUUID?.() ?? `cb-order-${Date.now()}-${Math.random().toString(36).slice(2)}`
}

async function createOrder() {
  createError.value = ''
  const planId = form.planId
  if (!planId) { createError.value = '请选择套餐。'; return }
  creating.value = true
  try {
    await portalApi.createOrder({ planId }, newIdempotencyKey())
    form.planId = ''
    showCreate.value = false
    await load()
  } catch (cause) {
    createError.value = getApiErrorMessage(cause)
  } finally { creating.value = false }
}

onMounted(() => { void Promise.all([load(), loadPlans()]) })
</script>

<template>
  <div class="portal-heading"><div><p class="eyebrow">账单记录</p><h1>订单</h1><p>查看套餐订单和支付状态。</p></div><div><button class="button button--secondary" type="button" :disabled="loading || creating" @click="load">{{ loading ? '加载中…' : '刷新' }}</button><button class="primary-button" type="button" :disabled="creating" @click="showCreate = !showCreate">{{ showCreate ? '关闭创建' : '创建订单' }}</button></div></div>
  <section v-if="showCreate" class="portal-panel order-form-panel"><h2>创建订单</h2><p>选择要购买的套餐。创建成功后仅显示服务端订单状态，不会在前端假定支付结果。</p><form class="order-form" @submit.prevent="createOrder"><label>套餐<select v-model="form.planId" :disabled="creating || plansLoading" required><option value="" disabled>{{ plansLoading ? '正在加载套餐…' : '请选择套餐' }}</option><option v-for="plan in plans" :key="plan.id" :value="plan.id">{{ plan.name }} · {{ money(plan.priceCents, plan.currency) }} / {{ plan.durationDays }} 天</option></select></label><p v-if="createError" class="form-error" role="alert">{{ createError }}</p><StatePanel v-if="plansError" title="套餐加载失败" :description="plansError" action-label="重试" @action="loadPlans"/><StatePanel v-else-if="!plansLoading && !plans.length" title="暂无可购买套餐" description="管理员尚未发布可购买套餐。"/><button class="primary-button" type="submit" :disabled="creating || plansLoading || !plans.length">{{ creating ? '创建中…' : '提交订单' }}</button></form></section>
  <section class="portal-panel"><StatePanel v-if="loading" title="正在加载订单" description="正在读取订单记录。"/><StatePanel v-else-if="error" title="订单加载失败" :description="error" action-label="重试" @action="load"/><StatePanel v-else-if="!orders.length" title="暂无订单" description="服务端尚未返回订单记录。"/><div v-else class="table-wrap"><table><thead><tr><th>订单</th><th>套餐</th><th>金额</th><th>状态</th><th>创建时间</th><th>支付时间</th></tr></thead><tbody><tr v-for="order in orders" :key="order.id"><td class="mono">{{ order.id }}</td><td>{{ order.plan }}</td><td>{{ money(order.amountCents, order.currency) }}</td><td><StatusBadge :status="order.status" /></td><td>{{ order.createdAt }}</td><td>{{ order.paidAt ?? '服务端未提供' }}</td></tr></tbody></table></div></section>
</template>
