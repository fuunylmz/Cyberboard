import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type { SessionUser } from '@cyberboard/types'
const storageKey = 'cyberboard.admin.session'
export const useAuthStore = defineStore('admin-auth', () => {
  const session = ref<SessionUser | null>(JSON.parse(localStorage.getItem(storageKey) ?? 'null'))
  const isAuthenticated = computed(() => Boolean(session.value))
  function login(email: string) { session.value = { id:'admin-demo', email, displayName:'系统管理员', roles:['admin'], permissions:['*'] }; localStorage.setItem(storageKey, JSON.stringify(session.value)) }
  function logout() { session.value = null; localStorage.removeItem(storageKey) }
  return { session, isAuthenticated, login, logout }
})
