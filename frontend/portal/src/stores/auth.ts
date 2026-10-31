import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type { SessionUser } from '@cyberboard/types'
import { portalAccessTokenKey, portalApi } from '../api'

const sessionKey = 'cyberboard.portal.session'
const expiresAtKey = 'cyberboard.portal.expiresAt'
const refreshTokenKey = 'cyberboard.portal.refreshToken'
function storageGet(key: string): string | null { try { return typeof window === 'undefined' ? null : window.localStorage.getItem(key) } catch { return null } }
function storageSet(key: string, value: string) { try { if (typeof window !== 'undefined') window.localStorage.setItem(key, value) } catch { /* Storage may be unavailable. */ } }
function storageRemove(key: string) { try { if (typeof window !== 'undefined') window.localStorage.removeItem(key) } catch { /* Storage may be unavailable. */ } }
function readSession(): SessionUser | null { try { return JSON.parse(storageGet(sessionKey) ?? 'null') as SessionUser | null } catch { return null } }
function readExpiresAt(): number | null { const value = Number(storageGet(expiresAtKey)); return Number.isFinite(value) && value > 0 ? value : null }

export const useAuthStore = defineStore('portal-auth', () => {
  const session = ref<SessionUser | null>(readSession())
  const accessToken = ref<string | null>(storageGet(portalAccessTokenKey))
  const expiresAt = ref<number | null>(readExpiresAt())
  const refreshToken = ref<string | null>(storageGet(refreshTokenKey))
  const sessionExpired = ref(false)
  const isAuthenticated = computed(() => Boolean(session.value && accessToken.value && (!expiresAt.value || expiresAt.value > Date.now())))
  let expiryTimer: number | undefined
  function persist() { if (session.value) storageSet(sessionKey, JSON.stringify(session.value)); else storageRemove(sessionKey); if (accessToken.value) storageSet(portalAccessTokenKey, accessToken.value); else storageRemove(portalAccessTokenKey); if (expiresAt.value) storageSet(expiresAtKey, String(expiresAt.value)); else storageRemove(expiresAtKey); if (refreshToken.value) storageSet(refreshTokenKey, refreshToken.value); else storageRemove(refreshTokenKey) }
  function logout(expired = false) { if (expiryTimer !== undefined && typeof window !== 'undefined') window.clearTimeout(expiryTimer); expiryTimer = undefined; sessionExpired.value = expired; session.value = null; accessToken.value = null; expiresAt.value = null; refreshToken.value = null; persist() }
  function scheduleExpiry() { if (typeof window === 'undefined' || !expiresAt.value) return; const delay = expiresAt.value - Date.now(); if (delay <= 0) { window.dispatchEvent(new CustomEvent('cyberboard:portal-unauthorized')); return } expiryTimer = window.setTimeout(() => window.dispatchEvent(new CustomEvent('cyberboard:portal-unauthorized')), delay) }
  async function applyLogin(result: Awaited<ReturnType<typeof portalApi.login>>) { sessionExpired.value = false; session.value = result.user; accessToken.value = result.accessToken; expiresAt.value = Date.now() + result.expiresIn * 1000; refreshToken.value = result.refreshToken ?? refreshToken.value; persist(); scheduleExpiry() }
  async function login(email: string, password: string) { await applyLogin(await portalApi.login({ email, password })) }
  async function refresh() { if (!refreshToken.value) return false; try { await applyLogin(await portalApi.refresh(refreshToken.value)); return true } catch { logout(true); return false } }
  if (expiresAt.value && expiresAt.value <= Date.now()) logout(true); else scheduleExpiry()
  return { session, accessToken, expiresAt, refreshToken, sessionExpired, isAuthenticated, login, refresh, logout }
})
