import { ApiClient, ApiError, createAdminApi, normalizeApiBaseUrl } from '@cyberboard/api-client'
import type { ListResponse } from '@cyberboard/types'

export const adminAccessTokenKey = 'cyberboard.admin.accessToken'
const baseUrl = normalizeApiBaseUrl(import.meta.env.VITE_API_BASE_URL)

export const adminApi = createAdminApi(new ApiClient({
  baseUrl,
  getAccessToken: () => typeof window === 'undefined' ? null : localStorage.getItem(adminAccessTokenKey),
  onUnauthorized: () => window.dispatchEvent(new CustomEvent('cyberboard:unauthorized')),
}))

export function normalizePage<T>(response: ListResponse<T>, page = 1, pageSize = 20) {
  return Array.isArray(response) ? { items: response, total: response.length, page, pageSize } : response
}

export function getApiErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const requestId = error.body.requestId ? `（请求 ID：${error.body.requestId}）` : ''
    const statusHint = error.status === 401 ? '登录已失效' : error.status === 403 ? '没有执行此操作的权限' : error.status === 409 ? '资源版本冲突，请刷新后重试' : error.status === 422 ? '提交数据未通过校验' : `请求失败（${error.status}）`
    const fields = error.body.fields ? `：${Object.entries(error.body.fields).map(([key, value]) => `${key} ${value}`).join('；')}` : ''
    return `${error.body.message || statusHint}${fields}${requestId}`
  }
  if (error instanceof Error && error.message) return error.message
  return '无法连接控制面 API，请检查服务状态后重试。'
}
