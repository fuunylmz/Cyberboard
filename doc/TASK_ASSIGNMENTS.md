# Cyberboard M1 任务分配计划

**创建时间**: 2026-11-02  
**项目主管**: AI Agent (Master)  
**子智能体模型**: gpt-6.1-sol  
**预计周期**: 2-3 周

## 任务优先级定义

- **P0**: 阻塞性任务,必须立即完成
- **P1**: 高优先级,M1 必需
- **P2**: 中优先级,可后延
- **P3**: 低优先级,M2 考虑

## 并行工作流

```
Week 1:
  Agent-Dev-1  →  [配置应用] [sing-box集成] [进程管理]
  Backend-Dev-1 → [配置生成] [订阅API] [签名集成]  
  Backend-Dev-2 → [流量统计] [上报API] [聚合逻辑]

Week 2:
  Frontend-Dev-1 → [API Client] [管理后台] [核心页面]
  Frontend-Dev-2 → [用户中心] [订阅下载] [使用量]
  Agent-Dev-1 → [回滚机制] [错误处理] [集成测试]

Week 3:
  Integration-1 → [端到端测试] [部署验证] [文档完善]
  All → [Bug 修复] [代码审查] [发布准备]
```

---

## Task Group 1: Agent 核心功能

### 任务 A1: sing-box 进程管理 【P0】

**负责人**: Agent-Dev-1  
**预计工时**: 2 天  
**依赖**: 无

**目标**:
- 实现 Agent 对 sing-box 进程的完整生命周期管理
- 支持启动、平滑重载、停止、健康检查

**交付物**:
1. `apps/agent/src/runtime/singbox.rs` - sing-box 适配器
2. 进程启动配置验证
3. 信号处理和优雅关闭
4. 健康检查探测逻辑
5. 单元测试覆盖

**验收标准**:
- [ ] 能够启动 sing-box 进程并读取 PID
- [ ] 配置文件变更时能平滑重载 (SIGHUP/USR1)
- [ ] 进程异常退出时能检测到并上报
- [ ] 健康检查失败时能触发重启
- [ ] 停止信号能优雅终止进程

**技术要点**:
```rust
// 期望接口设计
pub trait CoreRuntime {
    async fn start(&mut self, config_path: &Path) -> Result<()>;
    async fn reload(&mut self, config_path: &Path) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    async fn health_check(&self) -> Result<HealthStatus>;
    fn pid(&self) -> Option<u32>;
}
```

---

### 任务 A2: 配置应用流程 【P0】

**负责人**: Agent-Dev-1  
**预计工时**: 3 天  
**依赖**: 任务 A1, B1

**目标**:
- 实现 Agent 拉取、验证、应用配置的完整流程

**交付物**:
1. 配置拉取逻辑 (gRPC GetDesiredState)
2. Ed25519 签名验证
3. 配置原子写入和备份
4. 应用结果上报 (ReportApplyResult)
5. 集成测试

**验收标准**:
- [ ] 能从控制面拉取配置包
- [ ] 正确验证签名和 generation
- [ ] 拒绝过期、乱序、非目标节点的配置
- [ ] 原子替换配置文件 (tmp → rename)
- [ ] 应用成功/失败都能上报详细状态

**关键检查点**:
```rust
// 签名验证流程
1. 解析 SignedConfigEnvelope
2. 验证 target_node_id 匹配
3. 验证 generation >= current
4. 检查 expires_at
5. 验证 Ed25519 签名
6. 计算 content_hash 对比
```

---

### 任务 A3: 配置回滚机制 【P1】

**负责人**: Agent-Dev-1  
**预计工时**: 2 天  
**依赖**: 任务 A1, A2

**目标**:
- 配置应用失败时自动回滚到上一个可用版本

**交付物**:
1. 配置历史管理 (保留最近 3 个版本)
2. 回滚触发条件和逻辑
3. 回滚状态上报
4. 测试用例

**验收标准**:
- [ ] sing-box 启动失败时自动回滚
- [ ] 重载超时时自动回滚
- [ ] 健康检查持续失败时回滚
- [ ] 回滚后能成功恢复服务
- [ ] 回滚事件记录到日志和上报

---

### 任务 A4: 流量采集和上报 【P1】

**负责人**: Agent-Dev-1  
**预计工时**: 2 天  
**依赖**: 任务 A1, B3

**目标**:
- 实现流量统计采集和批量上报

**交付物**:
1. sing-box API 流量读取 (通过 API/文件)
2. 本地时间桶聚合
3. 批量上报逻辑 (ReportUsage gRPC)
4. 幂等键生成
5. 本地持久化队列

**验收标准**:
- [ ] 能从 sing-box 读取用户流量数据
- [ ] 按 5 分钟桶聚合
- [ ] 批量上报带幂等键
- [ ] 网络中断时本地队列不丢失
- [ ] 重传时不重复计费

**数据格式**:
```rust
pub struct UsageBatch {
    agent_id: Uuid,
    node_id: Uuid,
    time_start: DateTime<Utc>,
    time_end: DateTime<Utc>,
    sequence: u64,
    idempotency_key: String,
    user_usages: Vec<UserUsage>,
}
```

---

## Task Group 2: 后端核心功能

### 任务 B1: sing-box 配置生成 【P0】

**负责人**: Backend-Dev-1  
**预计工时**: 3 天  
**依赖**: 无

**目标**:
- 从统一配置模型生成 sing-box JSON 配置

**交付物**:
1. `crates/config-compiler/src/adapters/singbox.rs`
2. sing-box 配置结构体定义
3. 模板渲染逻辑
4. Golden test fixtures
5. 配置校验

**验收标准**:
- [ ] 能生成合法的 sing-box server config
- [ ] 支持 VLESS/VMess/Trojan 协议
- [ ] TLS 配置正确
- [ ] inbound/outbound 正确映射
- [ ] 生成的配置通过 sing-box check

**Golden Test**:
```rust
#[test]
fn test_vless_tls_config() {
    let model = load_fixture("vless_reality.json");
    let output = SingBoxAdapter::render(&model).unwrap();
    assert_json_eq!(output, load_golden("vless_reality.singbox.json"));
}
```

---

### 任务 B2: 订阅生成 API 【P1】

**负责人**: Backend-Dev-1  
**预计工时**: 2 天  
**依赖**: 任务 B1

**目标**:
- 实现 `/subscribe/{token}` 端点生成客户端订阅

**交付物**:
1. 订阅 Token 验证逻辑
2. 用户权限和节点过滤
3. sing-box client config 生成
4. 订阅访问审计
5. 限流保护

**验收标准**:
- [ ] 验证 Token 有效性和状态
- [ ] 只返回用户可访问的节点
- [ ] 生成的客户端配置能成功连接
- [ ] 访问记录到审计日志
- [ ] 限流 (每分钟 10 次)

**API 规范**:
```http
GET /subscribe/{token}?format=singbox&platform=ios
Response: application/json
{
  "log": {...},
  "inbounds": [...],
  "outbounds": [...],
  "route": {...}
}
```

---

### 任务 B3: 流量统计后端 【P1】

**负责人**: Backend-Dev-2  
**预计工时**: 3 天  
**依赖**: 无

**目标**:
- 实现流量上报接收、聚合、查询

**交付物**:
1. gRPC ReportUsage 接口实现
2. 幂等键验证和去重
3. 写入 usage_events 表
4. Worker 聚合任务 (events → buckets)
5. 查询 API

**验收标准**:
- [ ] 接收 Agent 批量上报
- [ ] 幂等键去重生效
- [ ] 原始事件写入 usage_events
- [ ] Worker 定期聚合到 usage_buckets
- [ ] 用户查询 API 返回正确统计

**数据流**:
```
Agent → ReportUsage gRPC → usage_events (追加)
                              ↓
                     Worker 聚合 (Redis Queue)
                              ↓
                     usage_buckets (时间桶汇总)
                              ↓
                     usage_daily (每日汇总)
```

---

### 任务 B4: 配置发布流程 【P1】

**负责人**: Backend-Dev-1  
**预计工时**: 2 天  
**依赖**: 任务 B1

**目标**:
- 完善配置发布、签名、版本管理

**交付物**:
1. POST `/api/v1/admin/config-revisions/{id}/publish` 实现
2. 签名生成集成
3. generation/CAS 逻辑
4. 目标节点筛选
5. 发布结果追踪

**验收标准**:
- [ ] 管理员能发布配置版本
- [ ] 自动生成 Ed25519 签名
- [ ] generation 递增且不可回退
- [ ] 只向匹配的节点发布
- [ ] 记录发布记录到 config_deployments

---

## Task Group 3: 前端实现

### 任务 F1: API Client 生成 【P0】

**负责人**: Frontend-Dev-1  
**预计工时**: 1 天  
**依赖**: 后端 OpenAPI 规范

**目标**:
- 生成类型安全的 TypeScript API Client

**交付物**:
1. OpenAPI 规范文件 (后端生成)
2. TypeScript 类型定义
3. 封装的 API Client
4. 错误处理统一
5. 使用文档

**验收标准**:
- [ ] 所有 API 有类型定义
- [ ] 自动携带 Authorization header
- [ ] 统一处理 401/403/422/5xx
- [ ] 支持 Idempotency-Key
- [ ] 请求/响应拦截器

**技术选型**:
- 工具: openapi-typescript / swagger-typescript-api
- HTTP 客户端: axios / ky

---

### 任务 F2: 管理后台核心页面 【P1】

**负责人**: Frontend-Dev-1  
**预计工时**: 5 天  
**依赖**: 任务 F1

**目标**:
- 实现管理后台核心功能页面

**交付物**:
1. Dashboard (总览)
2. 用户管理 (列表、详情、编辑)
3. 节点管理 (列表、注册、状态)
4. 套餐管理 (列表、创建、编辑)
5. 订阅管理 (列表、详情、操作)
6. 配置管理 (模板、发布、历史)

**验收标准**:
- [ ] 所有列表支持分页、搜索、筛选
- [ ] 表单验证完整
- [ ] 危险操作有二次确认
- [ ] 错误提示友好
- [ ] 加载状态和空状态
- [ ] 响应式布局

**UI 组件库决策**: 
- **推荐 Naive UI** (Vue 3 原生,TypeScript 友好)

---

### 任务 F3: 用户中心 【P1】

**负责人**: Frontend-Dev-2  
**预计工时**: 3 天  
**依赖**: 任务 F1

**目标**:
- 实现用户中心核心功能

**交付物**:
1. 用户首页 (订阅状态、流量)
2. 订阅下载页面
3. 使用量查看
4. 设备管理
5. 账户设置

**验收标准**:
- [ ] 用户能看到订阅状态和到期时间
- [ ] 能下载客户端配置
- [ ] 流量使用有图表展示
- [ ] 能轮换订阅 Token
- [ ] 移动端适配

---

### 任务 F4: 实时状态和推送 【P2】

**负责人**: Frontend-Dev-1  
**预计工时**: 2 天  
**依赖**: 任务 F2, 后端 SSE/WebSocket

**目标**:
- 节点状态、配置发布进度实时更新

**交付物**:
1. SSE/WebSocket 连接管理
2. 节点状态实时刷新
3. 配置发布进度展示
4. 断线重连逻辑

**验收标准**:
- [ ] 节点上线/离线实时反映
- [ ] 配置发布进度实时更新
- [ ] 连接断开后自动重连
- [ ] 降级到轮询

---

## Task Group 4: 集成和测试

### 任务 I1: 端到端流程测试 【P0】

**负责人**: Integration-1  
**预计工时**: 3 天  
**依赖**: 所有核心任务

**目标**:
- 验证完整业务闭环

**测试场景**:

1. **用户订阅流程**
   ```
   管理员创建用户 → 分配套餐 → 生成订阅
   → 用户获取订阅链接 → 下载配置 → 客户端连接
   ```

2. **节点配置流程**
   ```
   管理员创建节点 → 节点 Agent 注册
   → 创建配置模板 → 发布配置
   → Agent 拉取配置 → sing-box 启动
   ```

3. **流量统计流程**
   ```
   客户端产生流量 → sing-box 统计
   → Agent 上报 → 控制面聚合
   → 用户查看用量
   ```

4. **配置更新流程**
   ```
   修改配置 → 发布新版本 → Agent 拉取
   → 验证签名 → 平滑重载 → 上报结果
   ```

5. **回滚流程**
   ```
   发布错误配置 → sing-box 启动失败
   → Agent 检测失败 → 自动回滚
   → 恢复旧配置 → 上报回滚事件
   ```

**验收标准**:
- [ ] 5 个场景全部通过
- [ ] 每个场景有自动化测试脚本
- [ ] 失败场景有详细日志
- [ ] 性能指标记录

---

### 任务 I2: 单元测试补充 【P1】

**负责人**: 各模块负责人  
**预计工时**: 持续进行  
**目标覆盖率**: 60%+

**重点覆盖**:
- [ ] 配置生成逻辑
- [ ] 签名验证
- [ ] 流量聚合计算
- [ ] 权限校验
- [ ] Token 生成和验证

---

### 任务 I3: 部署文档和脚本 【P1】

**负责人**: Integration-1  
**预计工时**: 2 天  
**依赖**: 任务 I1

**目标**:
- 提供一键部署和快速启动

**交付物**:
1. 完整 Docker Compose 配置
2. 环境变量模板
3. 初始化脚本
4. 快速启动文档
5. 故障排查指南

**验收标准**:
- [ ] 新用户能在 10 分钟内启动完整系统
- [ ] 包含示例数据和测试账号
- [ ] 有完整的配置说明
- [ ] 常见问题 FAQ

---

## 代码审查流程

所有子智能体提交的代码必须经过主管审查:

### 审查清单

**功能正确性**:
- [ ] 实现符合需求
- [ ] 边界条件处理
- [ ] 错误处理完整

**代码质量**:
- [ ] 命名清晰
- [ ] 无重复代码
- [ ] 模块职责单一
- [ ] 有必要注释

**安全性**:
- [ ] 无 SQL 注入风险
- [ ] 密码/Token 不明文记录
- [ ] 权限校验到位
- [ ] 签名验证严格

**测试覆盖**:
- [ ] 核心逻辑有单元测试
- [ ] 边界场景有测试
- [ ] 测试可重复运行

**文档**:
- [ ] 复杂逻辑有注释
- [ ] 公共 API 有文档
- [ ] 配置项有说明

---

## 提交规范

### Commit Message 格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Type**:
- `feat`: 新功能
- `fix`: Bug 修复
- `refactor`: 重构
- `test`: 测试
- `docs`: 文档
- `chore`: 构建/工具

**示例**:
```
feat(agent): implement sing-box process management

- Add SingBoxRuntime struct
- Support start/reload/stop operations
- Add health check probe
- Include unit tests

Closes #12
```

---

## 沟通和汇报

### 日报模板

```markdown
## [Agent-Dev-1] 2026-11-03 工作日报

### 今日完成
- [A1] sing-box 进程启动和停止逻辑 ✅
- [A1] 健康检查探测实现 ✅

### 今日问题
- sing-box 重载信号在 macOS 和 Linux 不一致
  - 解决方案: 先尝试 SIGUSR1,fallback 到重启

### 明日计划
- [A1] 完成重载逻辑和测试
- [A2] 开始配置拉取实现

### 需要协助
- 请 Backend-Dev-1 提供签名验证示例代码
```

### 周报模板

```markdown
## Week 1 周报

### 整体进度
- A 组: 60% 完成
- B 组: 70% 完成  
- F 组: 40% 完成

### 本周亮点
- Agent 进程管理基本完成
- 配置生成通过 golden tests

### 风险和阻塞
- sing-box API 文档不全,需要代码阅读
- 前端 API Client 等待后端 OpenAPI

### 下周重点
- 打通配置发布完整流程
- 完成管理后台主要页面
```

---

## 里程碑检查点

### Checkpoint 1: 核心流程打通 (Week 1 结束)
- [ ] Agent 能拉取并应用配置
- [ ] sing-box 能成功启动
- [ ] 配置生成和签名工作

### Checkpoint 2: 前端基本可用 (Week 2 结束)
- [ ] 管理后台核心页面完成
- [ ] 用户中心基本功能完成
- [ ] API 集成正常

### Checkpoint 3: M1 发布候选 (Week 3 中)
- [ ] 端到端测试全部通过
- [ ] 部署文档完成
- [ ] 已知 Bug 修复

### M1 正式发布 (Week 3 结束)
- [ ] 所有 M1 验收标准达成
- [ ] Release notes 完成
- [ ] 演示环境就绪

---

## 资源分配

| 子智能体 | 任务组 | 预计工作量 | 优先级 |
|---------|--------|-----------|--------|
| Agent-Dev-1 | A1-A4 | 9 天 | P0 |
| Backend-Dev-1 | B1, B2, B4 | 7 天 | P0 |
| Backend-Dev-2 | B3 | 3 天 | P1 |
| Frontend-Dev-1 | F1, F2, F4 | 8 天 | P1 |
| Frontend-Dev-2 | F3 | 3 天 | P1 |
| Integration-1 | I1-I3 | 7 天 | P0 |

**并行度**: 最多 3 个子智能体同时工作  
**总工作量**: 约 37 人日  
**日历时间**: 2-3 周 (考虑返工和协调)

---

## 下一步行动

### 主管立即执行
1. ✅ 创建项目状态文档
2. ✅ 创建任务分配计划
3. ⏭️ 创建第一批子智能体
4. ⏭️ 分配初始任务
5. ⏭️ 建立代码审查流程

### 第一批启动任务
1. **Agent-Dev-1**: 任务 A1 (sing-box 进程管理)
2. **Backend-Dev-1**: 任务 B1 (配置生成)
3. **Backend-Dev-2**: 任务 B3 (流量统计)

---

**文档版本**: v1.0  
**最后更新**: 2026-11-02  
**负责人**: Project Master AI Agent
