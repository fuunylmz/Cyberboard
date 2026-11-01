# Cyberboard 项目状态

**复核日期**：2026-11-02
**当前阶段**：M1 功能集成与验收收尾
**结论**：核心功能代码已覆盖大部分 M1 范围；数据库仓储已通过隔离 PostgreSQL 实测，跨进程部署级端到端验收尚未完成，暂不宣称 M1 已发布或给出完成百分比。

## 已实现范围

| 领域 | 当前实现 | 验证边界 |
|---|---|---|
| 用户与管理员会话 | 持久化登录、会话和角色隔离 | Rust 单测及隔离 PostgreSQL API 认证测试通过 |
| 用户、套餐、订阅、订单 | API、数据库仓储和前后端主要页面 | 数据库全量测试通过；隔离 PostgreSQL 实测 |
| Agent 注册与心跳 | Agent 出站 gRPC、注册令牌生命周期及状态上报 | 代码和 Agent/API 单测覆盖 |
| 配置生成 | `ConfigProfile` 编译为 sing-box，VLESS、VMess、Trojan golden fixtures | config-compiler 测试通过；可用时执行 `sing-box check` |
| 配置发布与回滚 | 版本、签名 envelope、generation/CAS、部署记录和 roll-forward 回滚 | 数据库配置生命周期、迟到回执和回滚查询在隔离 PostgreSQL 实测通过 |
| Agent 配置应用 | 验签、节点/时间/hash 检查、原子安装、健康检查、回滚、结果重传；严格 CAS 失配拒绝，空可信状态可用签名全量配置恢复 | Agent 单元及集成测试通过 |
| 流量统计 | Agent 采集/重试、幂等入账、Worker 重建小时桶、用户和管理员查询 | 数据库用量入账、幂等和维护测试在隔离 PostgreSQL 实测通过 |
| 公共订阅 | 已应用节点配置、独立代理凭据、令牌轮换/撤销、no-store/no-referrer、审计及进程内限流 | 路由访问与撤销在隔离 PostgreSQL 实测通过；共享限流未实现，多实例需共享后端 |
| 管理端 / 用户端 | 管理、配置、订阅、订单、设备、安全、用量页面；新增管理员用量筛选和分页 | Admin 与 Portal 生产构建通过 |

## M1 尚未验收

项目规划将 M1 完成定义为从创建用户和节点，到生成配置并在节点成功加载的完整闭环。数据库仓储、配置发布/回滚、订阅查询、用量入账、凭据、审计和 API 持久化认证已经在隔离 PostgreSQL 17 上通过测试；仍缺少 API、Agent、sing-box 进程联动的部署级端到端演示，因此暂不关闭 M1。

本轮数据库验证使用临时 PostgreSQL 17 集群（绑定 `127.0.0.1:55432`，测试库独立于业务数据）。默认 shell 未设置 `CYBERBOARD_DATABASE_URL`，因此不带环境变量的数据库测试仍会走 skip 分支；本轮已显式设置连接串执行完整 workspace 测试。当前环境没有 Docker 命令，Compose 栈未运行。

## 剩余风险与技术债务

1. **P1：部署级端到端验收未执行。** 数据库集成已在隔离 PostgreSQL 17 上通过；仍需启动 API、Worker、Agent 和 sing-box，验证跨进程发布、应用、回滚、订阅拉取和流量查询。
2. **P1：订阅限流为进程内状态。** 当前为每 token 10 次/分钟、单进程总计 600 次/分钟；多 API 实例需要共享限流后端。限流审计采样为进程内，亦非跨实例共享。
3. **P2：Agent runtime 所有权存在重复抽象。** 生产流程仍由 `CoreSupervisor` 持有进程；独立 `runtime::singbox::SingBoxRuntime` API 未接入生产流程并产生 dead-code 警告。后续应统一抽象或移除重复实现。
4. **P2：管理员用量查询按原始事件动态聚合。** 适合 M1 小规模；数据量增长后需评估索引和预聚合。
5. **运维：** Compose 配置定义了 Redis，但本轮代码未验证 Redis 集成；生产密钥、TLS、备份与监控仍需部署验收。

## 验收下一步

1. 使用隔离 PostgreSQL 17 已通过配置生命周期、订阅仓储、用量、凭据、审计、迁移并发及 API 认证测试；后续数据库改动由 CI 自动执行同类集成测试。
2. 启动 API、Worker、Agent 和 sing-box，完成创建用户/订阅、配置发布、Agent 应用与回滚、订阅拉取及流量查询的部署级端到端验证。
3. 记录部署验证的 PostgreSQL、Agent 和核心版本，再决定 M1 是否关闭。

## 参考

- [项目规划](PROJECT_PLAN.md)：M0-M4 路线与 MVP 完成定义。
- [开发跟踪](DEVELOPMENT_TRACKING.md)：当前任务和验证记录。
- [任务分配初稿](TASK_ASSIGNMENTS.md)：启动时的工作拆分，不作为当前完成状态。
