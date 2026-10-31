import { ApiClient, ApiError, createPortalApi, normalizeApiBaseUrl } from '@cyberboard/api-client'

export const portalAccessTokenKey = 'cyberboard.portal.accessToken'
const baseUrl = normalizeApiBaseUrl(import.meta.env.VITE_API_BASE_URL)
export const portalApi = createPortalApi(new ApiClient({
  baseUrl,
  getAccessToken: () => typeof window === 'undefined' ? null : window.localStorage.getItem(portalAccessTokenKey),
  onUnauthorized: () => window.dispatchEvent(new CustomEvent('cyberboard:portal-unauthorized')),
}))
export function getApiErrorMessage(error: unknown): string {
  if (error instanceof ApiError) { const requestId = error.body.requestId ? `（请求 ID：${error.body.requestId}）` : ''; return `${error.body.message || `请求失败（${error.status}）`}${requestId}` }
  if (error instanceof Error && error.message) return error.message
  return '无法连接控制面 API，请检查服务状态后重试。'
}
