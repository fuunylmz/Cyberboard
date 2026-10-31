export type UserStatus = 'active' | 'suspended' | 'banned'
export type NodeStatus = 'online' | 'offline' | 'maintenance' | 'error'
export type SubscriptionStatus = 'active' | 'pending' | 'expired' | 'revoked'

export interface SessionUser { id: string; email: string; displayName: string; roles: string[]; permissions: string[] }
export interface UserSummary { id: string; email: string; displayName: string; status: UserStatus; plan: string; usedBytes: number; quotaBytes: number; expiresAt: string; lastSeenAt: string | null }
export interface NodeSummary { id: string; name: string; region: string; address: string; status: NodeStatus; core: string; coreVersion: string; agentVersion: string; currentConfigRevision: string; latencyMs: number | null; lastHeartbeatAt: string | null }
export interface SubscriptionSummary { id: string; userEmail: string; plan: string; status: SubscriptionStatus; trafficUsedBytes: number; trafficQuotaBytes: number; expiresAt: string; tokenHint: string }
export interface DashboardSummary { users: number; activeSubscriptions: number; onlineNodes: number; trafficBytes24h: number; failedTasks: number; generatedAt: string }
export interface ApiErrorBody { code: string; message: string; requestId?: string; fields?: Record<string, string> }
