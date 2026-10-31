import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type { SessionUser } from '@cyberboard/types'
import { adminAccessTokenKey, adminApi, refreshAdminSession } from '../api'

const sessionStorageKey = 'cyberboard.admin.session'
const expiresAtStorageKey = 'cyberboard.admin.expiresAt'
const refreshTokenStorageKey = 'cyberboard.admin.refreshToken'
function storageGet(key: string): string | null { try { return typeof window === 'undefined' ? null : window.localStorage.getItem(key) } catch { return null } }
function storageSet(key: string, value: string) { try { if (typeof window !== 'undefined') window.localStorage.setItem(key, value) } catch { /* Storage can be unavailable in restricted browser contexts. */ } }
function storageRemove(key: string) { try { if (typeof window !== 'undefined') window.localStorage.removeItem(key) } catch { /* Storage can be unavailable in restricted browser contexts. */ } }
function readSession(): SessionUser | null { try { return JSON.parse(storageGet(sessionStorageKey) ?? 'null') as SessionUser | null } catch { return null } }
function readExpiresAt(): number | null { const value = Number(storageGet(expiresAtStorageKey)); return Number.isFinite(value) && value > 0 ? value : null }

export const useAuthStore = defineStore('admin-auth', () => {
  const session = ref<SessionUser | null>(readSession())
  const accessToken = ref<string | null>(storageGet(adminAccessTokenKey))
  const expiresAt = ref<number | null>(readExpiresAt())
  const refreshToken = ref<string | null>(storageGet(refreshTokenStorageKey))
  const sessionExpired = ref(false)
  const isAuthenticated = computed(() => Boolean(session.value && accessToken.value && (!expiresAt.value || expiresAt.value > Date.now())))
  let expiryTimer: number | undefined
  function persist() { if (session.value) storageSet(sessionStorageKey, JSON.stringify(session.value)); else storageRemove(sessionStorageKey); if (accessToken.value) storageSet(adminAccessTokenKey, accessToken.value); else storageRemove(adminAccessTokenKey); if (expiresAt.value) storageSet(expiresAtStorageKey, String(expiresAt.value)); else storageRemove(expiresAtStorageKey); if (refreshToken.value) storageSet(refreshTokenStorageKey, refreshToken.value); else storageRemove(refreshTokenStorageKey) }
  function logout(expired = false) { if (expiryTimer !== undefined && typeof window !== 'undefined') window.clearTimeout(expiryTimer); expiryTimer = undefined; sessionExpired.value = expired; session.value = null; accessToken.value = null; expiresAt.value = null; refreshToken.value = null; persist() }
  function scheduleExpiry() { if (typeof window === 'undefined' || !expiresAt.value) return; const delay = expiresAt.value - Date.now(); if (delay <= 0) { logout(); return } expiryTimer = window.setTimeout(() => window.dispatchEvent(new CustomEvent('cyberboard:unauthorized')), delay) }
  async function applyLogin(result: Awaited<ReturnType<typeof adminApi.login>>) { sessionExpired.value = false; session.value = result.user; accessToken.value = result.accessToken; expiresAt.value = Date.now() + result.expiresIn * 1000; refreshToken.value = result.refreshToken ?? refreshToken.value; persist(); scheduleExpiry() }
  async function login(email: string, password: string) { await applyLogin(await adminApi.login({ email, password })) }
  async function refresh() { if (!refreshToken.value) return false; try { await applyLogin(await refreshAdminSession(refreshToken.value)); return true } catch { logout(true); return false } }
  if (expiresAt.value && expiresAt.value <= Date.now()) logout(true)
  else scheduleExpiry()
  return { session, accessToken, expiresAt, refreshToken, sessionExpired, isAuthenticated, login, refresh, logout }
})
