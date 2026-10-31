export type UserStatus = 'active' | 'suspended' | 'banned'
export type NodeStatus = 'online' | 'offline' | 'maintenance' | 'error'
export type SubscriptionStatus = 'active' | 'pending' | 'expired' | 'revoked'

export interface SessionUser { id: string; email: string; displayName: string; roles: string[]; permissions: string[] }
export interface LoginCredentials { email: string; password: string }
export interface LoginResponse { user: SessionUser; accessToken: string; tokenType: 'Bearer'; expiresIn: number }
export interface UserSummary { id: string; email: string; displayName: string; status: UserStatus; plan: string; usedBytes: number; quotaBytes: number; expiresAt: string; lastSeenAt: string | null }
export interface PageQuery { page?: number; pageSize?: number; search?: string; status?: string }
export interface PaginatedResponse<T> { items: T[]; total: number; page: number; pageSize: number }
export type ListResponse<T> = PaginatedResponse<T> | T[]
export interface UserCreateInput { email: string; displayName: string; password: string; status?: UserStatus; planId?: string }
export type UserUpdateInput = Partial<Omit<UserCreateInput, 'password'>> & { password?: string }
export interface PlanSummary { id: string; name: string; description: string; priceCents: number; currency: string; durationDays: number; quotaBytes: number; deviceLimit: number; status: 'active' | 'draft' | 'archived'; nodeGroupIds: string[] }
export interface PlanCreateInput { name: string; description?: string; priceCents: number; currency: string; durationDays: number; quotaBytes: number; deviceLimit: number; nodeGroupIds?: string[]; status?: PlanSummary['status'] }
export type PlanUpdateInput = Partial<PlanCreateInput>
export interface SubscriptionCreateInput { userId: string; planId: string; startsAt?: string }
export type SubscriptionUpdateInput = Partial<Pick<SubscriptionCreateInput, 'planId' | 'startsAt'>> & { status?: SubscriptionStatus }
export interface NodeCreateInput { name: string; region: string; address: string; port: number; core?: string; coreVersion?: string; tags?: string[] }
export type NodeUpdateInput = Partial<NodeCreateInput> & { status?: NodeStatus }
export interface UsageSummary { usedBytes: number; quotaBytes: number; todayBytes: number; projectedBytes: number; periodStart: string; periodEnd: string; daily: Array<{ date: string; bytes: number }> }
export interface ConfigTemplateSummary { id: string; name: string; description: string; coreType: string; coreVersionRange: string; status: 'draft' | 'active' | 'archived'; updatedAt: string; updatedBy: string }
export interface ConfigRevisionSummary { id: string; templateId: string; nodeId: string; nodeName: string; generation: number; coreVersion: string; contentHash: string; signatureStatus: 'pending' | 'valid' | 'invalid'; validationStatus: 'pending' | 'validated' | 'passed' | 'failed'; publishStatus: 'draft' | 'publishing' | 'published' | 'failed' | 'rolled_back'; failureReason?: string; createdAt: string }
export interface ConfigTemplateCreateInput { name: string; description?: string; coreType: string; coreVersionRange: string; status?: ConfigTemplateSummary['status'] }
export type ConfigTemplateUpdateInput = Partial<ConfigTemplateCreateInput>
export interface ConfigRevisionQuery extends PageQuery { templateId?: string; nodeId?: string }
export interface ConfigPublishInput { targetNodeIds?: string[]; expectedGeneration?: number }
export interface ConfigRollbackInput { expectedGeneration?: number; reason?: string }
export interface OrderSummary { id: string; plan: string; status: 'pending' | 'paid' | 'cancelled' | 'refunded' | 'failed'; amountCents: number; currency: string; createdAt: string; paidAt?: string | null }
export interface OrderCreateInput { planId: string }
export interface DeviceSummary { id: string; name: string; lastSeenAt: string | null; createdAt: string; revokedAt: string | null; platform?: string; status?: 'active' | 'revoked' | 'unknown'; ipAddress?: string }
export interface NodeSummary { id: string; name: string; region: string; address: string; status: NodeStatus; core: string; coreVersion: string; agentVersion: string; currentConfigRevision: string | null; latencyMs: number | null; lastHeartbeatAt: string | null }
export interface SubscriptionSummary { id: string; userEmail: string; plan: string; status: SubscriptionStatus; trafficUsedBytes: number; trafficQuotaBytes: number; expiresAt: string; tokenHint: string; subscriptionUrl?: string }
export interface DashboardSummary { users: number; activeSubscriptions: number; onlineNodes: number; trafficBytes24h: number; failedTasks: number; generatedAt: string }
export interface ApiErrorBody { code: string; message: string; requestId?: string; fields?: Record<string, string> }
