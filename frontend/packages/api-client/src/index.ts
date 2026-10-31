import type { ApiErrorBody, DashboardSummary, LoginCredentials, LoginResponse, NodeSummary, SessionUser, SubscriptionSummary, UserSummary } from '@cyberboard/types'

export interface ApiClientOptions { baseUrl?: string; getAccessToken?: () => string | null; onUnauthorized?: () => void }
export interface ApiRequestInit extends RequestInit { skipAuth?: boolean }
/** Accepts `/api`, an HTTP(S) origin, or an HTTP(S) URL ending in `/api`. */
export function normalizeApiBaseUrl(value: string | undefined): string {
  const configured = (value || '/api').replace(/\/+$/, '')
  if (configured === '/api' || configured.endsWith('/api')) return configured
  if (/^https?:\/\/[^/]+$/.test(configured)) return `${configured}/api`
  throw new Error('VITE_API_BASE_URL must be /api or an HTTP(S) origin ending in /api')
}
export class ApiError extends Error {
  constructor(public readonly status: number, public readonly body: ApiErrorBody) { super(body.message); this.name = 'ApiError' }
}
export class ApiClient {
  private readonly baseUrl: string
  constructor(private readonly options: ApiClientOptions = {}) { this.baseUrl = options.baseUrl ?? '/api' }
  private url(path: string): string {
    const base = this.baseUrl.replace(/\/+$/, '')
    let normalizedPath = path.startsWith('/') ? path : `/${path}`
    if (base.endsWith('/api') && normalizedPath.startsWith('/api/')) normalizedPath = normalizedPath.slice(4)
    return `${base}${normalizedPath}`
  }
  async request<T>(path: string, init: ApiRequestInit = {}): Promise<T> {
    const { skipAuth = false, ...requestInit } = init
    const headers = new Headers(requestInit.headers); headers.set('Accept', 'application/json')
    if (requestInit.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
    const token = skipAuth ? null : this.options.getAccessToken?.()
    const hasAuthorization = Boolean(headers.get('Authorization') || token)
    if (token && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${token}`)
    const response = await fetch(this.url(path), { ...requestInit, headers })
    const body = await response.json().catch(() => null) as T | ApiErrorBody | null
    if (response.status === 401 && hasAuthorization) this.options.onUnauthorized?.()
    if (!response.ok) throw new ApiError(response.status, (body ?? { code: 'unknown_error', message: response.statusText }) as ApiErrorBody)
    return body as T
  }
  get<T>(path: string) { return this.request<T>(path) }
  post<T>(path: string, value: unknown, init: ApiRequestInit = {}) { return this.request<T>(path, { ...init, method: 'POST', body: JSON.stringify(value) }) }
}
export interface AdminApi { login(credentials: LoginCredentials): Promise<LoginResponse>; getSession(): Promise<SessionUser>; getDashboard(): Promise<DashboardSummary>; listNodes(): Promise<NodeSummary[]>; listUsers(): Promise<UserSummary[]>; listSubscriptions(): Promise<SubscriptionSummary[]> }
export function createAdminApi(client: ApiClient): AdminApi { return { login: (credentials) => client.post('/v1/auth/login', credentials, { skipAuth: true }), getSession: () => client.get('/v1/session'), getDashboard: () => client.get('/v1/admin/dashboard'), listNodes: () => client.get('/v1/admin/nodes'), listUsers: () => client.get('/v1/admin/users'), listSubscriptions: () => client.get('/v1/admin/subscriptions') } }
export interface PortalApi { login(credentials: LoginCredentials): Promise<LoginResponse> }
export function createPortalApi(client: ApiClient): PortalApi { return { login: (credentials) => client.post('/v1/auth/portal-login', credentials, { skipAuth: true }) } }
