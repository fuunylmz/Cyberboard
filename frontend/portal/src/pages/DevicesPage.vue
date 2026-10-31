<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import type { DeviceSummary } from '@cyberboard/types'
import StatusBadge from '@cyberboard/ui/components/StatusBadge.vue'
import StatePanel from '@cyberboard/ui/components/StatePanel.vue'
import { getApiErrorMessage, normalizeList, portalApi } from '../api'

const loading = ref(true)
const error = ref('')
const actionError = ref('')
const devices = ref<DeviceSummary[]>([])
const revokingId = ref<string | null>(null)
const registering = ref(false)
const registerError = ref('')
const form = reactive({ name: '', fingerprint: '' })

const statusOf = (device: DeviceSummary) => device.status ?? (device.revokedAt ? 'revoked' : 'active')

async function load() {
  loading.value = true
  error.value = ''
  try { devices.value = normalizeList(await portalApi.listDevices({ page: 1, pageSize: 50 })) }
  catch (cause) { devices.value = []; error.value = getApiErrorMessage(cause) }
  finally { loading.value = false }
}

async function revoke(device: DeviceSummary) {
  if (!window.confirm(`确认撤销设备“${device.name}”？撤销后该设备需要重新登录。`)) return
  revokingId.value = device.id
  actionError.value = ''
  try { await portalApi.revokeDevice(device.id); await load() }
  catch (cause) { actionError.value = getApiErrorMessage(cause) }
  finally { revokingId.value = null }
}

async function register() {
  registerError.value = ''
  if (!form.name.trim() || !form.fingerprint.trim()) { registerError.value = '请输入设备名称和指纹。'; return }
  registering.value = true
  try { await portalApi.createDevice({ name: form.name.trim(), fingerprint: form.fingerprint.trim() }); form.name = ''; form.fingerprint = ''; await load() }
  catch (cause) { registerError.value = getApiErrorMessage(cause) }
  finally { registering.value = false }
}

onMounted(load)
</script>

<template>
  <div class="portal-heading"><div><p class="eyebrow">访问安全</p><h1>设备</h1><p>查看使用过订阅的设备和最近活动。</p></div><button class="button button--secondary" type="button" :disabled="loading" @click="load">{{ loading ? '加载中…' : '刷新' }}</button></div>
  <section class="portal-panel device-register"><h2>登记设备</h2><p>登记后可在达到套餐设备上限时明确管理已授权设备。</p><form @submit.prevent="register"><label>设备名称<input v-model="form.name" required :disabled="registering" placeholder="例如：MacBook" /></label><label>设备指纹<input v-model="form.fingerprint" required :disabled="registering" placeholder="客户端生成的稳定指纹" /></label><p v-if="registerError" class="form-error" role="alert">{{ registerError }}</p><button class="primary-button" type="submit" :disabled="registering">{{ registering ? '登记中…' : '登记设备' }}</button></form></section>
  <p v-if="actionError" class="form-error" role="alert">{{ actionError }}</p>
  <section class="portal-panel"><StatePanel v-if="loading" title="正在加载设备" description="正在读取设备活动。"/><StatePanel v-else-if="error" title="设备加载失败" :description="error" action-label="重试" @action="load"/><StatePanel v-else-if="!devices.length" title="暂无设备" description="服务端尚未返回设备记录。"/><div v-else class="device-list"><div v-for="device in devices" :key="device.id" class="device-row"><div><strong>{{ device.name }}</strong><small>{{ device.platform ?? '平台未提供' }} · {{ device.ipAddress ?? '地址未提供' }}</small></div><StatusBadge :status="statusOf(device)"/><span class="muted">{{ device.lastSeenAt ?? '从未活动' }}</span><button v-if="statusOf(device) !== 'revoked'" class="button button--secondary" type="button" :disabled="revokingId === device.id" @click="revoke(device)">{{ revokingId === device.id ? '撤销中…' : '撤销设备' }}</button><span v-else class="muted">已撤销</span></div></div></section>
</template>

<style scoped>
.device-register form { display: grid; gap: 12px; max-width: 560px; }
.device-register label { display: grid; gap: 6px; font-size: 12px; font-weight: 650; }
.device-register input { height: 38px; border: 1px solid var(--cb-border); border-radius: 6px; padding: 0 10px; background: var(--cb-surface); color: var(--cb-text); }
</style>
