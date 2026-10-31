import type { ApiErrorBody, DashboardSummary, NodeSummary, SessionUser, SubscriptionSummary, UserSummary } from '@cyberboard/types'

export interface ApiClientOptions { baseUrl?: string; getAccessToken?: () => string | null; onUnauthorized?: () => void }
export class ApiError extends Error {
  constructor(public readonly status: number, public readonly body: ApiErrorBody) { super(body.message); this.name = 'ApiError' }
}
export class ApiClient {
  private readonly baseUrl: string
  constructor(private readonly options: ApiClientOptions = {}) { this.baseUrl = options.baseUrl ?? '/api' }
  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers); headers.set('Accept', 'application/json')
    if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
    const token = this.options.getAccessToken?.(); if (token) headers.set('Authorization', `Bearer ${token}`)
    const response = await fetch(`${this.baseUrl}${path}`, { ...init, headers })
    const body = await response.json().catch(() => null) as T | ApiErrorBody | null
    if (response.status === 401) this.options.onUnauthorized?.()
    if (!response.ok) throw new ApiError(response.status, (body ?? { code: 'unknown_error', message: response.statusText }) as ApiErrorBody)
    return body as T
  }
  get<T>(path: string) { return this.request<T>(path) }
  post<T>(path: string, value: unknown) { return this.request<T>(path, { method: 'POST', body: JSON.stringify(value) }) }
}
export interface AdminApi { getSession(): Promise<SessionUser>; getDashboard(): Promise<DashboardSummary>; listNodes(): Promise<NodeSummary[]>; listUsers(): Promise<UserSummary[]>; listSubscriptions(): Promise<SubscriptionSummary[]> }
export function createAdminApi(client: ApiClient): AdminApi { return { getSession: () => client.get('/v1/session'), getDashboard: () => client.get('/v1/admin/dashboard'), listNodes: () => client.get('/v1/admin/nodes'), listUsers: () => client.get('/v1/admin/users'), listSubscriptions: () => client.get('/v1/admin/subscriptions') } }
