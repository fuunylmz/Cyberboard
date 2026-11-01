export type UserStatus = 'active' | 'suspended' | 'banned'
export type NodeStatus = 'online' | 'offline' | 'maintenance' | 'error'
export type SubscriptionStatus = 'active' | 'pending' | 'expired' | 'revoked'

export interface SessionUser { id: string; email: string; displayName: string; roles: string[]; permissions: string[] }
export interface LoginCredentials { email: string; password: string }
export interface LoginResponse { user: SessionUser; accessToken: string; tokenType: 'Bearer'; expiresIn: number; refreshToken?: string | null }
export interface UserSummary { id: string; email: string; displayName: string; status: UserStatus; plan: string; usedBytes: number; quotaBytes: number; expiresAt: string; lastSeenAt: string | null }
export interface PageQuery { page?: number; pageSize?: number; search?: string; status?: string }
export interface UsageQuery { userId?: string; nodeId?: string; startTime?: string | Date; endTime?: string | Date; page?: number; pageSize?: number; limit?: number; offset?: number }
export interface UsageRow { userId: string; username: string; nodeId: string | null; totalBytes: number; downloadBytes: number; uploadBytes: number; periodStart: string; periodEnd: string; eventCount: number }
export type UsageAggregate = UsageRow
export interface UsageResponse { items: UsageRow[]; total: number; page: number; pageSize: number; limit: number; offset: number }
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
export interface ConfigRevisionSummary { id: string; templateId: string; nodeId: string; nodeName: string; generation: number; coreVersion: string; contentHash: string; signatureStatus: 'pending' | 'valid' | 'invalid'; validationStatus: 'pending' | 'validated' | 'passed' | 'failed'; publishStatus: 'draft' | 'published' | 'rolled_back'; failureReason?: string; createdAt: string; deploymentStatus?: 'pending' | 'applied' | 'failed' | 'rolled_back' | null; deploymentKind?: 'publish' | 'rollback' | null; deploymentErrorCode?: string | null; deploymentErrorMessage?: string | null; deploymentUpdatedAt?: string | null; rollbackOf?: string | null }
export interface ConfigTemplateCreateInput { name: string; description?: string; coreType: string; coreVersionRange: string; status?: ConfigTemplateSummary['status'] }
export type ConfigTemplateUpdateInput = Partial<ConfigTemplateCreateInput>
export interface ConfigRevisionQuery extends PageQuery { templateId?: string; nodeId?: string }
export interface ConfigRevisionCreateInput { templateId: string; nodeId: string; generation: number; coreVersion: string; payload: Record<string, unknown> }
export interface ConfigPublishInput { targetNodeIds?: string[]; expectedGeneration?: number }
export interface ConfigRollbackInput { expectedGeneration?: number; reason?: string }
export interface OrderSummary { id: string; plan: string; status: 'pending' | 'paid' | 'cancelled' | 'refunded' | 'failed'; amountCents: number; currency: string; createdAt: string; paidAt?: string | null }
export interface OrderCreateInput { planId: string }
export interface AdminOrderSummary extends OrderSummary { userId: string; userEmail: string; provider?: string; providerPaymentId?: string | null }
export interface DeviceSummary { id: string; name: string; lastSeenAt: string | null; createdAt: string; revokedAt: string | null; platform?: string; status?: 'active' | 'revoked' | 'unknown'; ipAddress?: string }
export interface DeviceCreateInput { name: string; fingerprint: string }
export interface SessionSummary { id: string; role: string; issuedAt: string; expiresAt: string; revokedAt: string | null; active: boolean; current: boolean }
export interface PasswordChangeInput { currentPassword: string; newPassword: string }
export interface NodeSummary { id: string; name: string; region: string; address: string; status: NodeStatus; core: string; coreVersion: string; agentVersion: string; currentConfigRevision: string | null; desiredGeneration?: number | null; appliedConfigRevision?: string | null; appliedGeneration?: number | null; appliedAt?: string | null; coreState?: 'not_configured' | 'starting' | 'running' | 'reloading' | 'stopped' | 'crashed' | null; latencyMs: number | null; lastHeartbeatAt: string | null; memoryBytes?: number | null; cpuPercent?: number | null; trafficBytes24h?: number }
export interface AgentRegistrationToken { nodeId: string; token: string; expiresAt: number; rotated: boolean }
export interface AuditLogSummary { id: string; action: string; resourceType: string; resourceId: string | null; requestId: string | null; details: Record<string, unknown>; createdAt: string; actorUserId: string | null; actorEmail: string | null }
export interface SubscriptionSummary { id: string; userEmail: string; plan: string; status: SubscriptionStatus; trafficUsedBytes: number; trafficQuotaBytes: number; expiresAt: string; tokenHint: string; subscriptionUrl?: string }
export interface DashboardSummary { users: number; activeSubscriptions: number; onlineNodes: number; trafficBytes24h: number; failedTasks: number; generatedAt: string }
export interface ApiErrorBody { code: string; message: string; requestId?: string; fields?: Record<string, string> }
