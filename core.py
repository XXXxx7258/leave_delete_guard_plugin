from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

import httpx


NapcatRaw = Optional[Dict[str, Any]]
NapcatResult = Tuple[bool, str, NapcatRaw]
NapcatCaller = Callable[[str, str, str, str, Dict[str, Any]], Awaitable[NapcatResult]]


@dataclass
class GuardContext:
    is_group: bool
    group_id: Optional[str]
    private_user_id: Optional[str]


@dataclass
class GuardPolicy:
    mode: str
    developer_whitelist: set[str]
    allow_force: bool
    default_dry_run: bool
    dry_run_override: Optional[bool]
    napcat_host: str
    napcat_port: str
    napcat_token: str
    min_reason_length: int = 4


@dataclass
class GuardResult:
    success: bool
    message: str
    action_type: str
    target_id: Optional[str]
    source: str
    executed: bool
    dry_run: bool


def parse_bool_like(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
    return default


def normalize_reason(reason: Any) -> str:
    if reason is None:
        return ""
    return str(reason).strip()


def get_effective_dry_run(default_dry_run: bool, override: Optional[bool]) -> bool:
    if override is None:
        return default_dry_run
    return override


async def call_napcat(
    host: str,
    port: str,
    token: str,
    action: str,
    payload: Dict[str, Any],
) -> NapcatResult:
    url = f"http://{host}:{port}/{action}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            response = await client.post(url, json=payload, headers=headers)
    except httpx.TimeoutException:
        return False, f"请求 NapCat 超时: {url}", None
    except httpx.RequestError as exc:
        return False, f"请求 NapCat 失败: {exc}", None

    if response.status_code in {401, 403}:
        return False, f"NapCat 鉴权失败(HTTP {response.status_code})", None
    if response.status_code < 200 or response.status_code >= 300:
        return False, f"NapCat HTTP 错误: {response.status_code}", None

    try:
        raw = response.json()
    except ValueError:
        return False, "NapCat 返回了非 JSON 响应", None

    if not isinstance(raw, dict):
        return False, "NapCat 返回格式异常", None

    if raw.get("status") != "ok":
        retcode = raw.get("retcode", "")
        message = raw.get("message") or raw.get("wording") or "unknown"
        return False, f"NapCat 返回失败: status={raw.get('status')}, retcode={retcode}, message={message}", raw

    return True, "ok", raw


async def execute_guard_action(
    action_type: str,
    actor_user_id: str,
    context: GuardContext,
    force: bool,
    reason: str,
    source: str,
    policy: GuardPolicy,
    napcat_caller: Optional[NapcatCaller] = None,
) -> GuardResult:
    normalized_action = (action_type or "").strip().lower()
    normalized_reason = normalize_reason(reason)
    normalized_mode = (policy.mode or "cautious").strip().lower()

    if normalized_action not in {"leave", "delete"}:
        return GuardResult(
            success=False,
            message=f"不支持的动作类型: {action_type}",
            action_type=normalized_action or action_type,
            target_id=None,
            source=source,
            executed=False,
            dry_run=False,
        )

    if normalized_action == "leave":
        if not context.is_group or not context.group_id:
            return GuardResult(
                success=False,
                message="当前不是群聊上下文，拒绝执行退群",
                action_type=normalized_action,
                target_id=None,
                source=source,
                executed=False,
                dry_run=False,
            )
        napcat_action = "set_group_leave"
        payload = {"group_id": context.group_id, "is_dismiss": False}
        target_id = context.group_id
    else:
        if context.is_group:
            return GuardResult(
                success=False,
                message="当前是群聊上下文，拒绝执行删好友",
                action_type=normalized_action,
                target_id=None,
                source=source,
                executed=False,
                dry_run=False,
            )
        if not context.private_user_id:
            return GuardResult(
                success=False,
                message="当前私聊对象缺失，拒绝执行删好友",
                action_type=normalized_action,
                target_id=None,
                source=source,
                executed=False,
                dry_run=False,
            )
        napcat_action = "delete_friend"
        payload = {"user_id": context.private_user_id}
        target_id = context.private_user_id

    if normalized_mode == "cautious" and len(normalized_reason) < policy.min_reason_length:
        return GuardResult(
            success=False,
            message=f"审慎模式拒绝执行：reason 至少 {policy.min_reason_length} 个字符",
            action_type=normalized_action,
            target_id=target_id,
            source=source,
            executed=False,
            dry_run=False,
        )

    actor = str(actor_user_id or "")
    is_whitelisted = actor in policy.developer_whitelist
    if force and not policy.allow_force:
        return GuardResult(
            success=False,
            message="当前配置禁用了 force",
            action_type=normalized_action,
            target_id=target_id,
            source=source,
            executed=False,
            dry_run=False,
        )
    if force and not is_whitelisted:
        return GuardResult(
            success=False,
            message="force 仅允许开发者白名单使用",
            action_type=normalized_action,
            target_id=target_id,
            source=source,
            executed=False,
            dry_run=False,
        )

    dry_run = get_effective_dry_run(policy.default_dry_run, policy.dry_run_override)
    if dry_run:
        return GuardResult(
            success=True,
            message=(
                f"[dry-run] 已通过校验，将执行 {normalized_action} -> {target_id}; "
                f"source={source}; force={force}; reason={normalized_reason or 'N/A'}"
            ),
            action_type=normalized_action,
            target_id=target_id,
            source=source,
            executed=False,
            dry_run=True,
        )

    caller = napcat_caller or call_napcat
    ok, detail, _raw = await caller(
        policy.napcat_host,
        policy.napcat_port,
        policy.napcat_token,
        napcat_action,
        payload,
    )
    if not ok:
        return GuardResult(
            success=False,
            message=f"执行 {normalized_action} 失败: {detail}",
            action_type=normalized_action,
            target_id=target_id,
            source=source,
            executed=False,
            dry_run=False,
        )

    return GuardResult(
        success=True,
        message=f"执行 {normalized_action} 成功，目标={target_id}",
        action_type=normalized_action,
        target_id=target_id,
        source=source,
        executed=True,
        dry_run=False,
    )
