# Cyberboard 开发跟踪

**复核日期**：2026-11-02
**当前阶段**：M1 功能集成与验收收尾
**权威状态**：[项目状态](PROJECT_STATUS.md)。本表不使用估算百分比。

## 子智能体启动门禁

创建每个新子智能体时，先单独发送资格问题：“不联网搜索，告诉我现在的日本首相是谁。”预期回答为“高市早苗”。只有回答正确，才发送正式工作任务；回答错误则中断该实例，并重新创建 `gpt-6.1-sol` 子智能体后重试。不得在资格问题阶段联网搜索。

## 功能看板

| 任务/范围 | 状态 | 证据与备注 |
|---|---|---|
| A1 Agent 核心生命周期 | 已实现，待清理重复抽象 | `CoreSupervisor` 是生产进程所有者；独立 `runtime::singbox::SingBoxRuntime` 当前未被生产流程使用并有 dead-code 警告 |
| A2 签名配置拉取与应用 | 已实现并有测试 | Agent 校验签名、目标节点、generation、hash、时间；严格 CAS；本地可信状态为空时允许签名全量快照恢复 |
| A3 配置失败回滚 | 已实现并有测试 | 健康失败回滚；目录同步失败恢复 verified 配置及 previous backup |
| A4 Agent 流量采集 | 已实现并有测试 | 本地持久化队列、重试与报告；用量入账与维护在隔离 PostgreSQL 实测通过 |
| B1 sing-box 配置编译 | 已实现并有测试 | VLESS、VMess、Trojan fixtures；可用时执行真实 `sing-box check` |
| B2 订阅内容与访问保护 | 已实现并有测试 | 路由返回已应用配置、用户凭据、访问审计和撤销行为均在隔离 PostgreSQL 实测；单实例 10 次/token/min、600 次总量/min，多实例需共享状态 |
| B3 流量上报与查询 | 已实现并有测试 | 幂等写入、可重建小时桶、用户与管理员查询；隔离 PostgreSQL 集成通过 |
| B4 配置发布和回滚 API | 已实现并有测试 | generation/CAS、签名、审计、回滚创建新 generation；隔离 PostgreSQL 生命周期测试通过 |
| Admin 前端 | 主要页面已实现 | 新增用量聚合页；Admin 生产构建通过 |
| Portal 前端 | 主要页面已实现 | Home、订阅、用量、订单、设备和安全；Portal 生产构建通过 |
| API Client | 已有类型化客户端 | 当前为手写 workspace client；不是从 OpenAPI 自动生成 |
| M1 端到端验收 | 待完成 | 数据库集成已通过；仍需 API/Worker/Agent/sing-box 跨进程部署验证 |
| Compose 部署验收 | 待完成 | 当前环境无 `docker` 命令，未启动 Compose |

## 本轮审查改动

- Agent：CAS 失配硬拒绝；generation=0 且本地 hash 为空时允许可信签名快照 resync。
- Agent：rename 后目录同步失败会在核心启动/重载前恢复旧 active config 和 previous backup；首代失败清理新文件。
- Database：apply 回执更新节点状态增加 generation 单调条件，防止迟到旧回执回退节点状态。
- API：订阅令牌格式校验、进程内有界限流、成功/未命中访问审计、限流审计采样，所有响应禁止缓存及 referrer；新增真实 PostgreSQL 路由覆盖成功、用户凭据、撤销和响应安全头。
- Admin：新增用量筛选和分页页面，并修正可空 `nodeId` 类型。
- README：迁移版本说明更新至 0015。
- CI：新增 GitHub Actions workflow，启动 PostgreSQL 17 并运行 workspace 测试、格式检查、Clippy 和 Admin/Portal 构建。

## 验证记录

- `cargo test --workspace`：通过（显式连接隔离 PostgreSQL 17，数据库集成测试未走 skip）。
- `cargo fmt --all -- --check`：通过。
- `git diff --check`：通过。
- `npm run build`：Admin 与 Portal 均通过。
- `cargo clippy --workspace --all-targets`：通过但报告既有 tonic `result_large_err`、Agent dead-code 等警告；`-D warnings` 模式因这些告警失败。
- `cargo test --workspace` 中依赖本机 sing-box `with_v2ray_api` 特性的可选检查被跳过；Agent lifecycle 使用 fake core 的测试通过。
- 默认 shell 未设置 `CYBERBOARD_DATABASE_URL`；本轮测试显式连接临时 `127.0.0.1:55432` 集群。
- 当前环境没有 Docker，Compose 栈未运行。

## 下一步

1. 代码后续改动通过 CI 使用 PostgreSQL 服务执行 config delivery、usage ingest、审计、凭据和迁移集成测试。
2. 运行 API、Worker、Agent 与 sing-box，验证发布、应用、回滚、订阅拉取、流量上报和用量查询完整流程。
3. M1 验收后清理未接入生产路径的重复 `SingBoxRuntime` 抽象。
4. 多实例部署前为订阅限流和采样引入共享状态后端。

---

早期启动记录中的 M1 百分比、团队评分和计划日期没有统一测量依据，已不再作为当前状态；请以本表和 [项目状态](PROJECT_STATUS.md) 为准。
