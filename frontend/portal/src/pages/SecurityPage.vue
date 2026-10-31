<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import type { SessionSummary } from '@cyberboard/types'
import StatePanel from '@cyberboard/ui/components/StatePanel.vue'
import { getApiErrorMessage, normalizeList, portalApi } from '../api'

const sessions = ref<SessionSummary[]>([])
const loadingSessions = ref(true)
const sessionError = ref('')
const sessionActionError = ref('')
const revokingSessionId = ref<string | null>(null)
const password = reactive({ currentPassword: '', newPassword: '', confirmPassword: '' })
const passwordSaving = ref(false)
const passwordError = ref('')
const passwordNotice = ref('')

async function loadSessions() {
  loadingSessions.value = true
  sessionError.value = ''
  try { sessions.value = normalizeList(await portalApi.listSessions()) }
  catch (cause) { sessions.value = []; sessionError.value = getApiErrorMessage(cause) }
  finally { loadingSessions.value = false }
}

async function revokeSession(session: SessionSummary) {
  if (!window.confirm('确认撤销这个登录会话？该设备将需要重新登录。')) return
  revokingSessionId.value = session.id
  sessionActionError.value = ''
  try { await portalApi.revokeSession(session.id); await loadSessions() }
  catch (cause) { sessionActionError.value = getApiErrorMessage(cause) }
  finally { revokingSessionId.value = null }
}

async function changePassword() {
  passwordError.value = ''
  passwordNotice.value = ''
  if (password.newPassword.length < 8) { passwordError.value = '新密码至少需要 8 个字符。'; return }
  if (password.newPassword !== password.confirmPassword) { passwordError.value = '两次输入的新密码不一致。'; return }
  passwordSaving.value = true
  try {
    await portalApi.changePassword({ currentPassword: password.currentPassword, newPassword: password.newPassword })
    password.currentPassword = ''; password.newPassword = ''; password.confirmPassword = ''
    passwordNotice.value = '密码已更新，其他登录会话可能需要重新登录。'
    await loadSessions()
  } catch (cause) { passwordError.value = getApiErrorMessage(cause) }
  finally { passwordSaving.value = false }
}

onMounted(loadSessions)
</script>

<template>
  <div class="portal-heading"><div><p class="eyebrow">账户保护</p><h1>安全设置</h1><p>管理登录密码和已授权的会话。</p></div></div>
  <section class="portal-panel"><h2>修改密码</h2><p>使用至少 8 个字符的新密码。提交后由服务端校验当前密码。</p><form class="security-form" @submit.prevent="changePassword"><label>当前密码<input v-model="password.currentPassword" type="password" autocomplete="current-password" required :disabled="passwordSaving" /></label><label>新密码<input v-model="password.newPassword" type="password" autocomplete="new-password" minlength="8" required :disabled="passwordSaving" /></label><label>确认新密码<input v-model="password.confirmPassword" type="password" autocomplete="new-password" minlength="8" required :disabled="passwordSaving" /></label><p v-if="passwordError" class="form-error" role="alert">{{ passwordError }}</p><p v-if="passwordNotice" class="success-notice" role="status">{{ passwordNotice }}</p><button class="primary-button" type="submit" :disabled="passwordSaving">{{ passwordSaving ? '保存中…' : '更新密码' }}</button></form></section>
  <section class="portal-panel"><div class="section-heading"><div><h2>登录会话</h2><p>查看并撤销不再使用的登录会话。</p></div><button class="button button--secondary" type="button" :disabled="loadingSessions" @click="loadSessions">{{ loadingSessions ? '加载中…' : '刷新' }}</button></div><p v-if="sessionActionError" class="form-error" role="alert">{{ sessionActionError }}</p><StatePanel v-if="loadingSessions" title="正在加载会话" description="正在读取当前账户的登录会话。"/><StatePanel v-else-if="sessionError" title="会话加载失败" :description="sessionError" action-label="重试" @action="loadSessions"/><StatePanel v-else-if="!sessions.length" title="暂无会话记录" description="服务端尚未返回登录会话。"/><div v-else class="session-list"><div v-for="session in sessions" :key="session.id" class="session-row"><div><strong>{{ session.current ? '当前会话' : (session.role === 'admin' ? '管理员会话' : '用户会话') }}</strong><small>签发于 {{ session.issuedAt }} · 到期 {{ session.expiresAt }}</small></div><span class="muted">{{ session.active ? '有效' : (session.revokedAt ? '已撤销' : '已过期') }}</span><button v-if="session.active && !session.current" class="button button--secondary" type="button" :disabled="revokingSessionId === session.id" @click="revokeSession(session)">{{ revokingSessionId === session.id ? '撤销中…' : '撤销' }}</button><span v-else class="muted">{{ session.current ? '当前使用' : '不可操作' }}</span></div></div></section>
  <section class="portal-panel settings-list"><div><div><h2>二次认证</h2><p>二次认证入口预留，启用前不会改变当前登录流程。</p></div><button class="button button--secondary" type="button" disabled>暂未启用</button></div></section>
</template>

<style scoped>
.security-form { display: grid; gap: 14px; max-width: 620px; }
.security-form label { display: grid; gap: 7px; font-size: 12px; font-weight: 650; }
.security-form input { height: 39px; border: 1px solid var(--cb-border); border-radius: 6px; padding: 0 10px; background: var(--cb-surface); color: var(--cb-text); }
.security-form .primary-button { justify-self: start; }
.success-notice { margin: 0; color: var(--cb-success); font-size: 12px; }
.section-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; }
.section-heading h2 { margin-bottom: 8px; }
.session-list { display: grid; }
.session-row { display: flex; align-items: center; gap: 18px; padding: 15px 0; border-top: 1px solid var(--cb-border); }
.session-row > div { min-width: 0; flex: 1; }
.session-row strong, .session-row small { display: block; }
.session-row small { margin-top: 5px; color: var(--cb-text-muted); font-size: 11px; }
@media (max-width: 620px) { .session-row { align-items: flex-start; flex-wrap: wrap; } }
</style>
