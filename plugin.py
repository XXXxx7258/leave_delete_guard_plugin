from __future__ import annotations

from typing import Any, List, Optional, Tuple, Type

from src.common.logger import get_logger
from src.plugin_system import (
    ActionActivationType,
    BaseAction,
    BaseCommand,
    BasePlugin,
    ComponentInfo,
    ConfigField,
    register_plugin,
)

from .core import GuardContext, GuardPolicy, execute_guard_action, normalize_reason, parse_bool_like

logger = get_logger("leave_delete_guard_plugin")

_RUNTIME_DRY_RUN_OVERRIDE: Optional[bool] = None


def _get_nested(config: Optional[dict], key: str, default: Any) -> Any:
    if not config:
        return default
    current: Any = config
    for part in key.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


def _to_whitelist(values: Any) -> set[str]:
    if not isinstance(values, list):
        return set()
    return {str(item).strip() for item in values if str(item).strip()}


def _build_policy(plugin_config: Optional[dict]) -> GuardPolicy:
    mode = str(_get_nested(plugin_config, "security.mode", "cautious")).strip().lower()
    if mode not in {"cautious", "normal"}:
        logger.warning("security.mode=%s 非法，已回退为 cautious", mode)
        mode = "cautious"

    return GuardPolicy(
        mode=mode,
        developer_whitelist=_to_whitelist(_get_nested(plugin_config, "security.developer_whitelist", [])),
        allow_force=parse_bool_like(_get_nested(plugin_config, "security.allow_force", True), default=True),
        default_dry_run=parse_bool_like(_get_nested(plugin_config, "execution.default_dry_run", False), default=False),
        dry_run_override=_RUNTIME_DRY_RUN_OVERRIDE,
        napcat_host=str(_get_nested(plugin_config, "execution.napcat_host", "127.0.0.1")),
        napcat_port=str(_get_nested(plugin_config, "execution.napcat_port", "3000")),
        napcat_token=str(_get_nested(plugin_config, "execution.napcat_token", "")),
    )


def _set_runtime_dry_run_override(value: Optional[bool]) -> None:
    global _RUNTIME_DRY_RUN_OVERRIDE
    _RUNTIME_DRY_RUN_OVERRIDE = value


def _build_action_context(is_group: bool, group_id: Optional[str], user_id: Optional[str]) -> GuardContext:
    if is_group:
        return GuardContext(is_group=True, group_id=group_id, private_user_id=None)
    return GuardContext(is_group=False, group_id=None, private_user_id=user_id)


class LeaveDeleteGuardAction(BaseAction):
    action_name = "leave_delete_guard_action"
    action_description = "高风险自保动作：当遭遇严重侮辱、建政或极端危险言论时，退出当前群聊或删除当前私聊好友。"

    activation_type = ActionActivationType.ALWAYS
    keyword_case_sensitive = False
    parallel_action = False
    associated_types = ["text"]

    action_parameters = {
        "reason": "执行理由。应说明侮辱/建政/危险言论等触发依据；审慎模式下必须明确。",
    }
    action_require = [
        "这是高风险自保动作，默认不应使用。",
        "仅当出现严重侮辱、人身攻击、建政或其他极端危险言论时使用,若对方并无实质性语言，不能恶意揣测对方意图",
        "不要因为他人单纯要求“退群/删好友”就触发该动作。",
        "严禁跨上下文操作：群聊只能退当前群，私聊只能删当前对象。",
        "审慎模式下必须给出清晰且可解释的安全理由，理由过短会被拒绝。",
    ]

    async def execute(self) -> Tuple[bool, str]:
        force = False
        if "force" in self.action_data:
            logger.warning("%s planner action 提供了 force 参数，已忽略", self.log_prefix)
        reason = normalize_reason(self.action_data.get("reason")) or normalize_reason(self.action_reasoning)
        policy = _build_policy(self.plugin_config)

        context = _build_action_context(is_group=self.is_group, group_id=self.group_id, user_id=self.user_id)
        action_type = "leave" if context.is_group else "delete"
        actor_user_id = str(self.user_id or "")

        result = await execute_guard_action(
            action_type=action_type,
            actor_user_id=actor_user_id,
            context=context,
            force=force,
            reason=reason,
            source="planner",
            policy=policy,
        )

        await self.store_action_info(
            action_build_into_prompt=True,
            action_prompt_display=result.message,
            action_done=result.success,
        )
        logger.info(
            "%s planner action done: action=%s success=%s target=%s dry_run=%s",
            self.log_prefix,
            result.action_type,
            result.success,
            result.target_id,
            result.dry_run,
        )
        return result.success, result.message


class LeaveDeleteGuardCommand(BaseCommand):
    command_name = "leave_delete_guard_command"
    command_description = "开发者高风险调试命令：/ldg help|leave|delete|dryrun on|off"
    command_pattern = r"^/ldg(?:\s+(?P<subcmd>help|leave|delete|dryrun)(?:\s+(?P<arg1>force|on|off))?)?\s*$"

    async def execute(self) -> Tuple[bool, str, int]:
        text = (self.message.processed_plain_text or "").strip()
        parts = text.split()
        policy = _build_policy(self.plugin_config)
        actor_user_id = self._get_actor_user_id()

        if actor_user_id not in policy.developer_whitelist:
            denied = "无权限：/ldg 仅允许 developer_whitelist 用户使用。"
            await self.send_text(denied)
            return False, denied, 2

        if len(parts) == 1 or (len(parts) >= 2 and parts[1].lower() == "help"):
            help_text = self._help_text()
            await self.send_text(help_text)
            return True, "help displayed", 2

        subcmd = parts[1].lower()
        arg1 = parts[2].lower() if len(parts) >= 3 else ""
        if len(parts) > 3:
            message = "参数过多，请使用 /ldg help 查看命令格式。"
            await self.send_text(message)
            return False, message, 2

        if subcmd == "dryrun":
            if arg1 not in {"on", "off"}:
                message = "dryrun 命令格式错误，请使用 /ldg dryrun on|off"
                await self.send_text(message)
                return False, message, 2
            _set_runtime_dry_run_override(arg1 == "on")
            message = f"已设置运行时 dry_run={'ON' if arg1 == 'on' else 'OFF'}（仅当前进程有效）"
            await self.send_text(message)
            return True, message, 2

        if subcmd not in {"leave", "delete"}:
            message = "未知子命令，请使用 /ldg help。"
            await self.send_text(message)
            return False, message, 2

        force = False
        if arg1:
            if arg1 != "force":
                message = f"{subcmd} 子命令仅支持可选参数 force"
                await self.send_text(message)
                return False, message, 2
            force = True

        context = self._build_context_from_message()
        result = await execute_guard_action(
            action_type=subcmd,
            actor_user_id=actor_user_id,
            context=context,
            force=force,
            reason=f"command:{text}",
            source="command",
            policy=policy,
        )
        await self.send_text(self._format_result(result))
        return result.success, result.message, 2

    def _get_actor_user_id(self) -> str:
        user_info = getattr(getattr(self.message, "message_info", None), "user_info", None)
        user_id = getattr(user_info, "user_id", "")
        return str(user_id or "")

    def _build_context_from_message(self) -> GuardContext:
        message_info = getattr(self.message, "message_info", None)
        group_info = getattr(message_info, "group_info", None)
        user_info = getattr(message_info, "user_info", None)

        if group_info is not None:
            group_id = str(getattr(group_info, "group_id", "") or "")
            return GuardContext(is_group=True, group_id=group_id or None, private_user_id=None)

        private_user_id = str(getattr(user_info, "user_id", "") or "")
        return GuardContext(is_group=False, group_id=None, private_user_id=private_user_id or None)

    @staticmethod
    def _format_result(result) -> str:
        return (
            f"[ldg] success={result.success}\n"
            f"action={result.action_type}\n"
            f"target={result.target_id or 'N/A'}\n"
            f"dry_run={result.dry_run}\n"
            f"executed={result.executed}\n"
            f"detail={result.message}"
        )

    @staticmethod
    def _help_text() -> str:
        return (
            "leave_delete_guard_plugin 调试命令\n"
            "/ldg help\n"
            "/ldg leave [force]    # 群聊里退出当前群\n"
            "/ldg delete [force]   # 私聊里删除当前私聊对象好友\n"
            "/ldg dryrun on|off    # 设置进程内 dry-run\n"
            "注意：仅 developer_whitelist 用户可使用。"
        )


@register_plugin
class LeaveDeleteGuardPlugin(BasePlugin):
    plugin_name = "leave_delete_guard_plugin"
    enable_plugin = True
    dependencies: List[str] = []
    python_dependencies: List[str] = ["httpx"]
    config_file_name = "config.toml"

    config_section_descriptions = {
        "plugin": "插件基本设置",
        "security": "风险控制与权限",
        "execution": "NapCat 执行设置",
        "command": "调试命令设置",
    }

    config_schema: dict = {
        "plugin": {
            "enabled": ConfigField(type=bool, default=True, description="是否启用插件"),
            "config_version": ConfigField(type=str, default="1.0.0", description="配置文件版本"),
        },
        "security": {
            "mode": ConfigField(
                type=str,
                default="cautious",
                description="风险模式：cautious 或 normal",
                choices=["cautious", "normal"],
            ),
            "developer_whitelist": ConfigField(
                type=list,
                default=[],
                description="开发者白名单（字符串 user_id 列表）",
            ),
            "allow_force": ConfigField(type=bool, default=True, description="是否允许 force 强制执行"),
        },
        "execution": {
            "default_dry_run": ConfigField(type=bool, default=False, description="默认是否 dry-run（false=真实执行）"),
            "napcat_host": ConfigField(type=str, default="127.0.0.1", description="NapCat HTTP 服务地址"),
            "napcat_port": ConfigField(type=str, default="3000", description="NapCat HTTP 服务端口"),
            "napcat_token": ConfigField(type=str, default="", description="NapCat HTTP Token（可为空）"),
        },
        "command": {
            "prefix": ConfigField(type=str, default="/ldg", description="命令前缀（当前版本固定为 /ldg）"),
        },
    }

    def get_plugin_components(self) -> List[Tuple[ComponentInfo, Type]]:
        if not self.get_config("plugin.enabled", True):
            return []

        configured_prefix = str(self.get_config("command.prefix", "/ldg")).strip()
        if configured_prefix != "/ldg":
            logger.warning("command.prefix=%s 与固定前缀 /ldg 不一致，当前实现仍按 /ldg 匹配", configured_prefix)

        return [
            (LeaveDeleteGuardAction.get_action_info(), LeaveDeleteGuardAction),
            (LeaveDeleteGuardCommand.get_command_info(), LeaveDeleteGuardCommand),
        ]
