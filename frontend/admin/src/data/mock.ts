import type { DashboardSummary, NodeSummary, SubscriptionSummary, UserSummary } from '@cyberboard/types'
export const dashboard: DashboardSummary = { users:1284, activeSubscriptions:963, onlineNodes:18, trafficBytes24h:8420000000000, failedTasks:2, generatedAt:new Date().toISOString() }
export const nodes: NodeSummary[] = [
  { id:'node-sg-01', name:'Singapore 01', region:'SG', address:'sg-01.example.net', status:'online', core:'sing-box', coreVersion:'1.11.0', agentVersion:'0.3.0', currentConfigRevision:'rev-20261031-18', latencyMs:82, lastHeartbeatAt:new Date().toISOString() },
  { id:'node-tokyo-02', name:'Tokyo 02', region:'JP', address:'jp-02.example.net', status:'maintenance', core:'sing-box', coreVersion:'1.10.7', agentVersion:'0.3.0', currentConfigRevision:'rev-20261030-11', latencyMs:null, lastHeartbeatAt:new Date(Date.now()-720000).toISOString() },
  { id:'node-fra-01', name:'Frankfurt 01', region:'DE', address:'de-01.example.net', status:'offline', core:'sing-box', coreVersion:'1.11.0', agentVersion:'0.2.4', currentConfigRevision:'rev-20261029-07', latencyMs:null, lastHeartbeatAt:new Date(Date.now()-2100000).toISOString() },
]
export const users: UserSummary[] = [
  { id:'usr-1001', email:'lin@example.com', displayName:'Lin', status:'active', plan:'Pro 1000GB', usedBytes:420000000000, quotaBytes:1000000000000, expiresAt:'2026-12-18', lastSeenAt:new Date().toISOString() },
  { id:'usr-1002', email:'alex@example.com', displayName:'Alex', status:'active', plan:'Basic 200GB', usedBytes:198000000000, quotaBytes:200000000000, expiresAt:'2026-11-02', lastSeenAt:new Date(Date.now()-2700000).toISOString() },
  { id:'usr-1003', email:'mira@example.com', displayName:'Mira', status:'suspended', plan:'Basic 200GB', usedBytes:0, quotaBytes:200000000000, expiresAt:'2026-10-29', lastSeenAt:null },
]
export const subscriptions: SubscriptionSummary[] = [
  { id:'sub-2001', userEmail:'lin@example.com', plan:'Pro 1000GB', status:'active', trafficUsedBytes:420000000000, trafficQuotaBytes:1000000000000, expiresAt:'2026-12-18', tokenHint:'cb_••••_8f21' },
  { id:'sub-2002', userEmail:'alex@example.com', plan:'Basic 200GB', status:'active', trafficUsedBytes:198000000000, trafficQuotaBytes:200000000000, expiresAt:'2026-11-02', tokenHint:'cb_••••_a9c4' },
  { id:'sub-2003', userEmail:'mira@example.com', plan:'Basic 200GB', status:'expired', trafficUsedBytes:0, trafficQuotaBytes:200000000000, expiresAt:'2026-10-29', tokenHint:'cb_••••_e102' },
]
