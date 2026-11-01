# sing-box with V2Ray API

Cyberboard 按独立进程调用 sing-box，不把 sing-box 代码链接进 Apache-2.0 项目。上游 v1.14.4 默认构建没有 `with_v2ray_api`，遇到 `experimental.v2ray_api` 配置会直接拒绝启动。启用该功能后，所有使用此配置的节点都必须运行本构建，不能混用 Homebrew 或官方默认构建。

## 构建内容

[`build.sh`](build.sh) 锁定上游 `v1.14.4`，并校验其提交为 `c005f35300ce76427dc285481ec5695f5b179cd2`。脚本从该源码的 `release/DEFAULT_BUILD_TAGS` 和 `release/LDFLAGS` 读取默认标签及链接参数，不修改上游源码。

上游默认标签全部保留，唯一移除的是 `with_naive_outbound`：这是客户端出站功能，服务端不需要，而且会引入 cronet 原生库。额外添加 `with_v2ray_api`。未因目标平台移除其他标签；如将来有平台构建失败，应先记录具体平台、错误和无法替代的功能，再决定是否缩减。

构建默认目标是本机 `darwin/arm64`、生产 `linux/amd64` 和 `linux/arm64`。脚本设 `CGO_ENABLED=0`，以避免交叉编译依赖目标平台 C 工具链、头文件和原生库；产物因此不包含依赖 CGO 的实现。当前目标均以 CGO 关闭成功构建。Go 模块校验保持启用，没有使用 `GOSUMDB=off`、`GONOSUMDB` 或 `-mod=mod` 绕过校验。Go 构建缓存和脚本自动获取的源码 checkout 都放在 `$TMPDIR/sing-box-build`，不会进入 Cyberboard 工作树。

## 构建和校验

需要 Bash、Git 和 Go。默认产物写入 `/Users/fuunylmz/Cyberboard/.worktrees/bin/`；可用 `SING_BOX_OUTPUT_DIR` 覆盖。可用 `SING_BOX_TARGETS="linux/amd64 linux/arm64"` 选择目标，用 `SING_BOX_SOURCE_DIR` 指定已 checkout 的上游源码（必须是未经修改的精确 tag），用 `SING_BOX_BUILD_TMP` 变更临时源码和缓存目录。

```sh
deploy/sing-box/build.sh
/Users/fuunylmz/Cyberboard/.worktrees/bin/sing-box version
shasum -a 256 /Users/fuunylmz/Cyberboard/.worktrees/bin/sing-box
```

版本命令应显示 `sing-box version 1.14.4`，且 Tags 包含 `with_v2ray_api`。脚本对每个构建产物打印 SHA-256。Linux 目标文件名分别为 `sing-box-linux-amd64` 和 `sing-box-linux-arm64`。跨平台产物只能在对应目标系统上执行验证。

最小多用户配置示例（认证口令仅作示例，部署时必须替换）：

```json
{
  "inbounds": [{
    "type": "mixed",
    "tag": "users-in",
    "listen": "127.0.0.1",
    "listen_port": 18150,
    "users": [
      { "username": "alice", "password": "replace-this" },
      { "username": "bob", "password": "replace-this-too" }
    ]
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "final": "direct" },
  "experimental": {
    "v2ray_api": {
      "listen": "127.0.0.1:18151",
      "stats": { "enabled": true, "users": ["alice", "bob"] }
    }
  }
}
```

V2Ray API 的 StatsService 是无 TLS、无认证的 gRPC 接口，只应监听回环地址或被严密隔离的管理网络。计数器格式为 `user>>>NAME>>>traffic>>>uplink` 和 `user>>>NAME>>>traffic>>>downlink`；只有配置在 `stats.users` 中且入站用户名非空的用户会被统计。启用 `reset=true` 会读取并清零匹配计数器；进程重载/重启会重置内存计数。注意：v1.14.4 的 `experimental/v2rayapi/stats.go` 在初始化时将注册服务名覆写为 `v2ray.core.app.stats.command.StatsService`，与 `stats.proto` 声明的 `experimental.v2rayapi.StatsService` 以及生成客户端中的方法路径不同。调用端应按实际服务端路径请求，或显式覆盖生成客户端的 RPC 路径。

## 本机验证

以包含两个用户及 `experimental.v2ray_api` 的同一配置分别运行 `check`：本构建成功（退出码 0，无输出），Homebrew 1.14.4 默认构建失败（退出码 1），报错原文为：

```text
FATAL v2ray api is not included in this build, rebuild with -tags with_v2ray_api
```

本机冒烟测试通过：两个用户分别用 SOCKS5 认证访问回环 HTTP 服务，QueryStats 中各自 uplink 为 78 bytes、downlink 为 1,033,302 bytes。`reset=true` 返回四个正计数，之后查询为空；再次产生流量并发送 SIGHUP 重载后查询也为空。测试监听仅使用 127.0.0.1:18150-18152，完成后已停止服务。

## 许可与分发

sing-box 按 GPL-3.0 发布。本项目将它作为独立进程调用，不链接其代码。合规提醒（非法律意见）：若将此 sing-box 二进制分发给第三方，应同时提供对应源码，即未修改的上游 `v1.14.4` tag 加上本构建脚本，并保留适用的许可和版权信息。

本轮不把内核二进制分发到节点；现有发布机制只分发 Agent。后续需要单独设计内核产物的发布、校验和升级流程。
