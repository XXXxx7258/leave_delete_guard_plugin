# leave_delete_guard_plugin

高风险退群插件：在严格策略下执行退群/删好友。

## 功能

- Planner Action：在群聊仅允许退出当前群，在私聊仅允许删除当前私聊对象好友。
- 调试命令：`/ldg help | /ldg leave [force] | /ldg delete [force] | /ldg dryrun on|off`。
- 风控策略：`cautious` 模式下必须提供足够长度的理由。
- 执行通道：NapCat HTTP API（`set_group_leave`、`delete_friend`）。

## 配置

由插件系统自动生成 `config.toml`，关键项如下：

- `plugin.enabled`
- `security.mode`：`cautious` 或 `normal`
- `security.developer_whitelist`：可使用 `/ldg` 的 user_id 列表
- `security.allow_force`：是否允许 `force`
- `execution.default_dry_run`：默认 dry-run 开关
- `execution.napcat_host` / `execution.napcat_port` / `execution.napcat_token`
- `command.prefix`：当前版本固定 `/ldg`

## 风险提示

- 这是高风险插件，建议先 `dry-run` 再真实执行。
- 插件只允许当前上下文目标，不支持外部传参指定 target。
- `force` 仅对白名单用户生效。

## 使用方式

- 在napcat页面配置对于http服务器
