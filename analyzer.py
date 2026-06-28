# -*- coding: UTF-8 -*-
# @Project: PythonPracticeLab
# @File   : data_analyze.py
# @Author : Xavier Wu
# @Date   : 2026/6/26 15:00
#
# 事件分析引擎：对 Santa 事件进行分类、摘要提取和报告生成。
# 26 种事件类型按安全关注点分为 7 大类，生成统计报告和安全告警。
# 事件数据结构定义: Source/common/santa.proto

from dataclasses import dataclass
from collections import defaultdict


# ─── 事件分类与安全等级 ──────────────────────────────────────────────────────
#
# Santa 定义了 26 种事件类型（SantaMessage.oneof event），按安全关注点分为 7 大类。
# 安全等级（severity）说明：
#   CRITICAL - 需要立即关注：恶意软件、权限提升、执行被拒绝
#   HIGH     - 需要尽快关注：敏感文件操作、认证失败、策略变更
#   MEDIUM   - 常规关注：进程生命周期、网络活动、用户会话
#   LOW      - 信息性：磁盘挂载、Bundle 收集、代码签名变更
#
# 事件数据结构定义: Source/common/santa.proto
#   SantaMessage (line 1266) → oneof event 包含以下 26 种事件：

# 26 种事件类型的完整清单，对应 SantaMessage.oneof event 的每个字段
EVENT_TYPES = [
    "execution", "fork", "exit", "close", "rename", "unlink", "link",
    "exchangedata", "disk", "bundle", "allowlist", "file_access",
    "codesigning_invalidated", "login_window_session", "login_logout",
    "screen_sharing", "open_ssh", "authentication", "clone", "copyfile",
    "gatekeeper_override", "launch_item", "tcc_modification", "xprotect",
    "network_activity", "proc_suspend_resume",
]


@dataclass
class EventCategory:
    """事件分类定义"""
    name: str
    description: str
    severity: str
    event_types: list[str]


# 7 大安全分类
EVENT_CATEGORIES = {
    # ─────────────────────────────────────────────────────────────────────
    # ① 进程执行与控制（Process Execution & Control）
    # 核心安全事件：Santa 的主要功能就是控制哪些程序可以运行
    # 关键关注：decision=DENY 表示执行被阻止，audit_return=True 表示审计命中
    #
    # Execution 关键字段:
    #   - instigator: ProcessInfoLight，触发 exec 的父进程
    #   - target: ProcessInfo，新执行的进程（含签名、CDHash、entitlements）
    #   - decision: DECISION_ALLOW / DECISION_DENY / DECISION_ALLOW_COMPILER
    #   - reason: 决策依据（REASON_BINARY/REASON_CERT/REASON_TEAM_ID/...）
    #   - mode: MODE_LOCKDOWN / MODE_MONITOR / MODE_STANDALONE
    #   - quarantine_url: 从哪下载的（LaunchServices quarantine 属性）
    #   - entitlement_info: 该二进制拥有的 entitlement 列表
    #   - rule_id: 服务端下发的规则 ID
    #
    # Fork 关键字段:
    #   - instigator: 调用 fork() 的进程
    #   - child: 新创建的子进程
    #
    # Exit 关键字段:
    #   - instigator: 退出的进程
    #   - ExitType: exited(exit_status) 或 signaled(signal) 或 stopped(signal)
    # ─────────────────────────────────────────────────────────────────────
    "process_execution": EventCategory(
        name="进程执行与控制",
        description="进程创建、执行决策、退出 — Santa 的核心安全控制点",
        severity="CRITICAL",
        event_types=["execution", "fork", "exit"],
    ),

    # ─────────────────────────────────────────────────────────────────────
    # ② 文件操作（File Operations）
    # 追踪文件的创建、修改、删除、重命名等行为
    # 关键关注：敏感路径的操作、被修改的文件（close.modified=True）
    #
    # Close 关键字段:
    #   - instigator: 关闭文件的进程
    #   - target: FileInfo（路径 + stat + hash）
    #   - modified: bool，文件在打开期间是否被写入
    #
    # Rename 关键字段:
    #   - instigator: 执行重命名的进程
    #   - source: FileInfo，原文件
    #   - target: string，新路径
    #   - target_existed: bool，目标路径是否已存在（覆盖风险）
    #
    # Unlink 关键字段:
    #   - instigator: 删除文件的进程
    #   - target: FileInfo，被删除的文件
    #
    # Link 关键字段:
    #   - instigator: 创建硬链接的进程
    #   - source: FileInfo，原文件
    #   - target: string，新链接路径
    #
    # Clone 关键字段:
    #   - instigator: 克隆文件的进程
    #   - source: FileInfo，原文件
    #   - target: string，克隆后的路径
    #
    # Copyfile 关键字段:
    #   - instigator: 调用 copyfile 系统调用的进程
    #   - source/target: 源和目标
    #   - mode: copyfile 的 mode 参数
    #   - flags: copyfile 的 flags 参数
    #
    # Exchangedata 关键字段:
    #   - instigator: 交换数据的进程
    #   - file1, file2: 两个 FileInfo（仅适用于非 APFS 文件系统）
    # ─────────────────────────────────────────────────────────────────────
    "file_operations": EventCategory(
        name="文件操作",
        description="文件的关闭/重命名/删除/链接/克隆/复制 — 追踪文件系统变更",
        severity="MEDIUM",
        event_types=["close", "rename", "unlink", "link",
                     "exchangedata", "clone", "copyfile"],
    ),

    # ─────────────────────────────────────────────────────────────────────
    # ③ 文件访问授权（File Access Authorization）
    # Santa 的 FAA（File Access Authorization）策略引擎产生的事件
    # 关键关注：policy_decision=DENIED 表示访问被阻止
    #
    # FileAccess 关键字段:
    #   - instigator: ProcessInfo（完整进程信息，比 Light 版更详细）
    #   - target: FileInfo，被访问的文件
    #   - policy_name: 触发的策略名称
    #   - policy_version: 策略版本
    #   - access_type: OPEN/RENAME/UNLINK/LINK/CLONE/... 等操作类型
    #   - policy_decision: DENIED / DENIED_INVALID_SIGNATURE / ALLOWED_AUDIT_ONLY
    #   - operation_id: 关联同一操作的多个事件
    #   - rule_id: 服务端规则 ID
    #
    # Allowlist 关键字段:
    #   - instigator: 触发 allowlist 规则生成的进程
    #   - target: FileInfo，新 allowlist 规则覆盖的文件
    # ─────────────────────────────────────────────────────────────────────
    "file_access": EventCategory(
        name="文件访问授权",
        description="FAA 策略引擎的访问控制决策和 allowlist 规则生成",
        severity="HIGH",
        event_types=["file_access", "allowlist"],
    ),

    # ─────────────────────────────────────────────────────────────────────
    # ④ 认证与会话（Authentication & Sessions）
    # 用户登录/登出/锁屏/远程访问等身份认证事件
    # 关键关注：认证失败、远程登录、权限提升
    #
    # LoginWindowSession 关键字段 (oneof event):
    #   - login: 用户登录（含 user + graphical_session）
    #   - logout: 用户登出
    #   - lock: 锁屏
    #   - unlock: 解锁
    #
    # LoginLogout 关键字段 (oneof event):
    #   - login: login(1) 命令登录（含 success + failure_message）
    #   - logout: login(1) 命令登出
    #
    # ScreenSharing 关键字段 (oneof event):
    #   - attach: 屏幕共享连接（含 success + source + authentication_type）
    #   - detach: 屏幕共享断开
    #
    # OpenSSH 关键字段 (oneof event):
    #   - login: SSH 登录（含 result 枚举：AUTH_SUCCESS/AUTH_FAIL_*/...）
    #   - logout: SSH 登出
    #
    # Authentication 关键字段 (oneof event + success):
    #   - authentication_od: OpenDirectory 认证（record_type + record_name + node_name）
    #   - authentication_touch_id: Touch ID 认证（mode: VERIFICATION/IDENTIFICATION）
    #   - authentication_token: 令牌认证（pubkey_hash + token_id + kerberos_principal）
    #   - authentication_auto_unlock: Apple Watch 自动解锁（TYPE_MACHINE_UNLOCK/AUTH_PROMPT）
    # ─────────────────────────────────────────────────────────────────────
    "auth_session": EventCategory(
        name="认证与会话",
        description="用户登录/登出/SSH/屏幕共享/TouchID — 身份认证追踪",
        severity="HIGH",
        event_types=["login_window_session", "login_logout",
                     "screen_sharing", "open_ssh", "authentication"],
    ),

    # ─────────────────────────────────────────────────────────────────────
    # ⑤ 系统安全策略（System Security Policy）
    # 系统级安全配置的变更事件
    # 关键关注：Gatekeeper 被绕过、TCC 权限变更、启动项添加
    #
    # GatekeeperOverride 关键字段:
    #   - instigator: 创建覆盖的进程
    #   - target: FileInfo，被覆盖 Gatekeeper 策略的文件
    #   - code_signature: 该文件的代码签名信息
    #
    # TCCModification 关键字段:
    #   - instigator: 触发 TCC 变更的进程
    #   - service: TCC 服务名（如 "kTCCServiceCamera"）
    #   - identity: 被授权/撤权的应用标识
    #   - identity_type: BUNDLE_ID / EXECUTABLE_PATH / POLICY_ID
    #   - event_type: CREATE / MODIFY / DELETE
    #   - authorization_right: DENIED / ALLOWED / LIMITED
    #   - authorization_reason: USER_CONSENT / MDM_POLICY / ENTITLED / ...
    #
    # LaunchItem 关键字段:
    #   - instigator: 报告事件的进程
    #   - action: ADD / REMOVE
    #   - item_type: USER_ITEM / APP / LOGIN_ITEM / AGENT / DAEMON
    #   - managed: bool，是否由 MDM 管理
    #   - item_path: 启动项路径
    #   - executable_path: plist 中定义的可执行文件路径
    # ─────────────────────────────────────────────────────────────────────
    "system_policy": EventCategory(
        name="系统安全策略",
        description="Gatekeeper 覆盖、TCC 权限变更、启动项增删 — 系统安全基线监控",
        severity="HIGH",
        event_types=["gatekeeper_override", "tcc_modification", "launch_item"],
    ),

    # ─────────────────────────────────────────────────────────────────────
    # ⑥ 恶意软件检测（Malware Detection）
    # XProtect 引擎的检测结果
    # 关键关注：所有 detected 事件都需要立即关注
    #
    # XProtect 关键字段 (oneof event):
    #   - detected:
    #       - signature_version: 签名库版本
    #       - malware_identifier: 恶意软件名称
    #       - incident_identifier: 关联 detected+remediated 事件的 ID
    #       - detected_path: 检测到恶意软件的路径
    #   - remediated:
    #       - action_type: 处理动作（如 "path_delete"）
    #       - success: 是否成功
    #       - result_description: 失败/成功的具体原因
    #       - remediated_path: 被处理的路径
    #       - remediated_process_id: 被处理的进程 ID
    # ─────────────────────────────────────────────────────────────────────
    "malware": EventCategory(
        name="恶意软件检测",
        description="XProtect 恶意软件检测与修复 — 需要立即响应",
        severity="CRITICAL",
        event_types=["xprotect"],
    ),

    # ─────────────────────────────────────────────────────────────────────
    # ⑦ 网络活动与设备（Network & Devices）
    # 网络连接和外接设备事件
    #
    # NetworkActivity 关键字段:
    #   - processes[]: 每个进程的网络活动
    #     - process: ProcessInfo（完整进程信息）
    #     - flows[]: 该进程的网络流列表
    #       - remote_address + remote_port: 远端地址
    #       - local_address + local_port: 本地地址
    #       - protocol: IP 协议号（6=TCP, 17=UDP）
    #       - socket_family: INET / INET6
    #       - direction: INBOUND / OUTBOUND
    #       - bytes_inbound + bytes_outbound: 累计字节数
    #       - start_time + close_time: 流的起止时间
    #   注意: event_time 和 processed_time 是监控窗口的起止时间
    #
    # Disk 关键字段:
    #   - action: APPEARED / DISAPPEARED / BLOCKED
    #   - mount: 挂载路径
    #   - volume: 卷名
    #   - model: 设备型号
    #   - serial: 序列号
    #   - bus: 总线协议（USB/Thunderbolt/...）
    #   - encrypted: 是否加密
    #   - dmg_path: DMG 镜像路径（如适用）
    # ─────────────────────────────────────────────────────────────────────
    "network_device": EventCategory(
        name="网络活动与设备",
        description="网络流量监控和外接设备事件 — 数据外泄与介质控制",
        severity="MEDIUM",
        event_types=["network_activity", "disk"],
    ),

    # ─────────────────────────────────────────────────────────────────────
    # 补充：进程状态与辅助信息
    #
    # Bundle 关键字段:
    #   - file_hash: 触发事件的文件 hash
    #   - bundle_hash: 整个 Bundle 的 hash（所有可执行文件的 hash 的 hash）
    #   - bundle_name + bundle_id + bundle_path: Bundle 标识
    #   - path: 触发事件的具体文件路径
    #
    # CodesigningInvalidated 关键字段:
    #   - instigator: 代码签名失效的进程
    #
    # ProcSuspendResume 关键字段:
    #   - instigator: 发起挂起/恢复的进程
    #   - target: 被操作的进程
    #   - type: SUSPEND / RESUME / SHUTDOWN_SOCKETS
    # ─────────────────────────────────────────────────────────────────────
    "process_misc": EventCategory(
        name="进程状态与辅助",
        description="Bundle 收集、代码签名变更、进程挂起/恢复 — 辅助信息",
        severity="LOW",
        event_types=["bundle", "codesigning_invalidated",
                     "proc_suspend_resume"],
    ),
}

# 构建事件类型 → 分类的快速查找表
EVENT_TYPE_TO_CATEGORY: dict[str, EventCategory] = {}
for cat in EVENT_CATEGORIES.values():
    for et in cat.event_types:
        EVENT_TYPE_TO_CATEGORY[et] = cat


def get_event_type(message: dict) -> str | None:
    """从 SantaMessage dict 中提取事件类型名称。
    SantaMessage 的 oneof event 字段中，只有一个会被设置，
    在 dict 中表现为只有一个事件类型的 key 存在。
    """
    for et in EVENT_TYPES:
        if et in message:
            return et
    return None


def classify_message(message: dict) -> EventCategory:
    """将一条 SantaMessage 归类到对应的安全分类"""
    et = get_event_type(message)
    if et and et in EVENT_TYPE_TO_CATEGORY:
        return EVENT_TYPE_TO_CATEGORY[et]
    return EventCategory(name="未知", description="未分类的事件",
                         severity="MEDIUM", event_types=[])


# ─── 事件摘要提取 ────────────────────────────────────────────────────────────
#
# 每种事件类型定义了一组"关键字段提取器"，从嵌套的 dict 中抽取
# 最核心的信息用于报告展示，避免输出大量无关细节。

def _get(d: dict | None, *keys: str, default=""):
    """安全地从嵌套 dict 中取值: _get(d, "target", "executable", "path")"""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur


def _proc_name(proc: dict | None) -> str:
    """从 ProcessInfo/ProcessInfoLight 中提取可读的进程标识"""
    if not proc:
        return "?"
    path = _get(proc, "executable", "path")
    pid = _get(proc, "id", "pid")
    if path and pid:
        return f"{path} (pid={pid})"
    return path or f"pid={pid}" or "?"


def summarize_event(message: dict) -> dict:
    """从一条 SantaMessage 提取关键摘要信息，返回精简 dict"""
    event_type = get_event_type(message)
    event_data = message.get(event_type, {}) if event_type else {}
    category = classify_message(message)
    ts = _get(message, "event_time")

    summary = {
        "event_id": message.get("event_id", ""),
        "timestamp": ts,
        "event_type": event_type,
        "category": category.name,
        "severity": category.severity,
        "machine_id": message.get("machine_id", ""),
    }

    match event_type:
        case "execution":
            decision = _get(event_data, "decision")
            summary.update({
                "description": "进程执行",
                "process": _proc_name(_get(event_data, "target")),
                "parent": _proc_name(_get(event_data, "instigator")),
                "decision": decision,
                "reason": _get(event_data, "reason"),
                "mode": _get(event_data, "mode"),
                "args": event_data.get("args", []),
                "quarantine_url": _get(event_data, "quarantine_url"),
                "signing_id": _get(event_data, "target", "code_signature", "signing_id"),
                "team_id": _get(event_data, "target", "code_signature", "team_id"),
                "rule_id": _get(event_data, "rule_id"),
                "highlight": decision in ("DECISION_DENY",),
            })
        case "fork":
            summary.update({
                "description": "进程 fork",
                "parent": _proc_name(_get(event_data, "instigator")),
                "child": _proc_name(_get(event_data, "child")),
                "highlight": False,
            })
        case "exit":
            exit_type = "exited" if "exited" in event_data else \
                        "signaled" if "signaled" in event_data else \
                        "stopped" if "stopped" in event_data else "unknown"
            summary.update({
                "description": f"进程退出 ({exit_type})",
                "process": _proc_name(_get(event_data, "instigator")),
                "exit_info": event_data.get(exit_type, {}),
                "highlight": False,
            })
        case "close":
            modified = event_data.get("modified", False)
            summary.update({
                "description": f"文件关闭{' (已修改)' if modified else ''}",
                "process": _proc_name(_get(event_data, "instigator")),
                "file": _get(event_data, "target", "path"),
                "modified": modified,
                "highlight": modified,
            })
        case "rename":
            summary.update({
                "description": "文件重命名",
                "process": _proc_name(_get(event_data, "instigator")),
                "source": _get(event_data, "source", "path"),
                "target": _get(event_data, "target"),
                "target_existed": event_data.get("target_existed", False),
                "highlight": event_data.get("target_existed", False),
            })
        case "unlink":
            summary.update({
                "description": "文件删除",
                "process": _proc_name(_get(event_data, "instigator")),
                "file": _get(event_data, "target", "path"),
                "highlight": True,
            })
        case "link":
            summary.update({
                "description": "硬链接创建",
                "process": _proc_name(_get(event_data, "instigator")),
                "source": _get(event_data, "source", "path"),
                "target": _get(event_data, "target"),
                "highlight": False,
            })
        case "exchangedata":
            summary.update({
                "description": "文件数据交换",
                "process": _proc_name(_get(event_data, "instigator")),
                "file1": _get(event_data, "file1", "path"),
                "file2": _get(event_data, "file2", "path"),
                "highlight": False,
            })
        case "disk":
            action = _get(event_data, "action")
            summary.update({
                "description": f"磁盘事件 ({action})",
                "mount": _get(event_data, "mount"),
                "volume": _get(event_data, "volume"),
                "model": _get(event_data, "model"),
                "serial": _get(event_data, "serial"),
                "bus": _get(event_data, "bus"),
                "encrypted": event_data.get("encrypted"),
                "highlight": action == "ACTION_BLOCKED",
            })
        case "bundle":
            summary.update({
                "description": "Bundle 信息采集",
                "bundle_name": _get(event_data, "bundle_name"),
                "bundle_id": _get(event_data, "bundle_id"),
                "bundle_path": _get(event_data, "bundle_path"),
                "path": _get(event_data, "path"),
                "highlight": False,
            })
        case "allowlist":
            summary.update({
                "description": "Allowlist 规则生成",
                "process": _proc_name(_get(event_data, "instigator")),
                "file": _get(event_data, "target", "path"),
                "highlight": False,
            })
        case "file_access":
            policy_decision = _get(event_data, "policy_decision")
            summary.update({
                "description": "文件访问授权",
                "process": _proc_name(_get(event_data, "instigator")),
                "file": _get(event_data, "target", "path"),
                "policy_name": _get(event_data, "policy_name"),
                "access_type": _get(event_data, "access_type"),
                "policy_decision": policy_decision,
                "rule_id": _get(event_data, "rule_id"),
                "highlight": "DENIED" in policy_decision,
            })
        case "codesigning_invalidated":
            summary.update({
                "description": "代码签名失效",
                "process": _proc_name(_get(event_data, "instigator")),
                "highlight": True,
            })
        case "login_window_session":
            # 嵌套 oneof: login / logout / lock / unlock
            sub_type = next((k for k in ("login", "logout", "lock", "unlock")
                             if k in event_data), "unknown")
            user = _get(event_data, sub_type, "user", "name")
            summary.update({
                "description": f"LoginWindow {sub_type}",
                "user": user,
                "highlight": sub_type in ("login", "unlock"),
            })
        case "login_logout":
            sub_type = next((k for k in ("login", "logout")
                             if k in event_data), "unknown")
            sub_data = event_data.get(sub_type, {})
            summary.update({
                "description": f"终端{sub_type}",
                "user": _get(sub_data, "user", "name"),
                "success": sub_data.get("success"),
                "failure_message": _get(sub_data, "failure_message"),
                "highlight": sub_type == "login" and not sub_data.get("success", True),
            })
        case "screen_sharing":
            sub_type = next((k for k in ("attach", "detach")
                             if k in event_data), "unknown")
            sub_data = event_data.get(sub_type, {})
            summary.update({
                "description": f"屏幕共享 {sub_type}",
                "source": _get(sub_data, "source", "address"),
                "success": sub_data.get("success"),
                "viewer": _get(sub_data, "viewer"),
                "highlight": sub_type == "attach" and sub_data.get("success"),
            })
        case "open_ssh":
            sub_type = next((k for k in ("login", "logout")
                             if k in event_data), "unknown")
            sub_data = event_data.get(sub_type, {})
            result = _get(sub_data, "result")
            summary.update({
                "description": f"SSH {sub_type}",
                "source": _get(sub_data, "source", "address"),
                "user": _get(sub_data, "user", "name"),
                "result": result,
                "highlight": sub_type == "login" and result != "RESULT_AUTH_SUCCESS",
            })
        case "authentication":
            success = event_data.get("success", False)
            sub_type = next((k for k in ("authentication_od", "authentication_touch_id",
                                         "authentication_token", "authentication_auto_unlock")
                             if k in event_data), "unknown")
            summary.update({
                "description": f"认证 ({sub_type.replace('authentication_', '')})",
                "success": success,
                "highlight": not success,
            })
        case "clone":
            summary.update({
                "description": "文件克隆",
                "process": _proc_name(_get(event_data, "instigator")),
                "source": _get(event_data, "source", "path"),
                "target": _get(event_data, "target"),
                "highlight": False,
            })
        case "copyfile":
            summary.update({
                "description": "文件复制 (copyfile syscall)",
                "process": _proc_name(_get(event_data, "instigator")),
                "source": _get(event_data, "source", "path"),
                "target": _get(event_data, "target"),
                "highlight": False,
            })
        case "gatekeeper_override":
            summary.update({
                "description": "Gatekeeper 策略覆盖",
                "process": _proc_name(_get(event_data, "instigator")),
                "file": _get(event_data, "target", "path"),
                "signing_id": _get(event_data, "code_signature", "signing_id"),
                "highlight": True,
            })
        case "launch_item":
            action = _get(event_data, "action")
            summary.update({
                "description": f"启动项 {action}",
                "item_type": _get(event_data, "item_type"),
                "item_path": _get(event_data, "item_path"),
                "executable_path": _get(event_data, "executable_path"),
                "managed": event_data.get("managed", False),
                "highlight": action == "ACTION_ADD",
            })
        case "tcc_modification":
            event_type_val = _get(event_data, "event_type")
            summary.update({
                "description": f"TCC 权限变更 ({event_type_val})",
                "service": _get(event_data, "service"),
                "identity": _get(event_data, "identity"),
                "authorization_right": _get(event_data, "authorization_right"),
                "authorization_reason": _get(event_data, "authorization_reason"),
                "highlight": event_type_val in ("EVENT_TYPE_CREATE", "EVENT_TYPE_MODIFY"),
            })
        case "xprotect":
            sub_type = next((k for k in ("detected", "remediated")
                             if k in event_data), "unknown")
            sub_data = event_data.get(sub_type, {})
            summary.update({
                "description": f"XProtect {sub_type}",
                "malware": _get(sub_data, "malware_identifier"),
                "path": _get(sub_data, "detected_path") or _get(sub_data, "remediated_path"),
                "success": sub_data.get("success"),
                "highlight": sub_type == "detected",
            })
        case "network_activity":
            procs = event_data.get("processes", [])
            flow_count = sum(len(p.get("flows", [])) for p in procs)
            summary.update({
                "description": f"网络活动 ({len(procs)} 进程, {flow_count} 流)",
                "process_count": len(procs),
                "flow_count": flow_count,
                "highlight": False,
            })
        case "proc_suspend_resume":
            summary.update({
                "description": f"进程{_get(event_data, 'type').replace('TYPE_', '').lower()}",
                "instigator": _proc_name(_get(event_data, "instigator")),
                "target": _proc_name(_get(event_data, "target")),
                "highlight": False,
            })
        case _:
            summary.update({"description": "未知事件", "highlight": False})

    return summary


# ─── 报告生成 ────────────────────────────────────────────────────────────────

def generate_report(messages: list[dict]) -> dict:
    """生成完整的事件分析报告"""
    summaries = [summarize_event(m) for m in messages]

    # 按分类统计
    category_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    event_type_counts = defaultdict(int)
    highlights = []
    denied_executions = []
    denied_file_access = []

    for s in summaries:
        cat_name = s["category"]
        cat = next((c for c in EVENT_CATEGORIES.values() if c.name == cat_name), None)
        severity = cat.severity if cat else "MEDIUM"

        category_counts[cat_name] += 1
        severity_counts[severity] += 1
        event_type_counts[s["event_type"]] += 1

        if s.get("highlight"):
            highlights.append(s)

        if s["event_type"] == "execution" and s.get("decision") == "DECISION_DENY":
            denied_executions.append(s)
        if s["event_type"] == "file_access" and "DENIED" in str(s.get("policy_decision", "")):
            denied_file_access.append(s)

    return {
        "overview": {
            "total_events": len(summaries),
            "unique_event_types": len(event_type_counts),
            "time_range": {
                "earliest": min((s["timestamp"] for s in summaries if s["timestamp"]), default=None),
                "latest": max((s["timestamp"] for s in summaries if s["timestamp"]), default=None),
            },
        },
        "severity_breakdown": dict(severity_counts),
        "category_breakdown": dict(category_counts),
        "event_type_breakdown": dict(sorted(event_type_counts.items(), key=lambda x: -x[1])),
        "highlights": highlights,
        "security_alerts": {
            "denied_executions": denied_executions,
            "denied_file_access": denied_file_access,
            "xprotect_detections": [s for s in highlights if s["event_type"] == "xprotect"],
            "gatekeeper_overrides": [s for s in highlights if s["event_type"] == "gatekeeper_override"],
            "auth_failures": [s for s in highlights if s["category"] == "认证与会话"],
        },
        "all_events": summaries,
    }


def print_report(report: dict):
    """打印可读的事件报告"""
    import json
    ov = report["overview"]

    print("=" * 70)
    print("                    Santa 事件安全报告")
    print("=" * 70)
    print(f"  事件总数:    {ov['total_events']}")
    print(f"  事件类型数:  {ov['unique_event_types']}")
    print(f"  时间范围:    {ov['time_range']['earliest']}")
    print(f"              → {ov['time_range']['latest']}")
    print()

    # 安全等级分布
    print("── 安全等级分布 " + "─" * 54)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = report["severity_breakdown"].get(sev, 0)
        if count:
            bar = "█" * min(count, 50)
            print(f"  {sev:<10} {count:>5}  {bar}")
    print()

    # 分类统计
    print("── 事件分类统计 " + "─" * 54)
    for cat_name, count in sorted(report["category_breakdown"].items(), key=lambda x: -x[1]):
        print(f"  {cat_name:<20} {count:>5}")
    print()

    # 事件类型 Top 10
    print("── 事件类型 Top 10 " + "─" * 52)
    for et, count in list(report["event_type_breakdown"].items())[:10]:
        print(f"  {et:<30} {count:>5}")
    print()

    # 安全告警
    alerts = report["security_alerts"]
    has_alerts = any(v for v in alerts.values())

    if has_alerts:
        print("── ⚠ 安全告警 " + "─" * 56)

        if alerts["denied_executions"]:
            print(f"\n  [{len(alerts['denied_executions'])}] 被拒绝的执行:")
            for s in alerts["denied_executions"][:5]:
                print(f"    - {s['process']}")
                print(f"      决策: {s['decision']} / 原因: {s['reason']}")
                if s.get("quarantine_url"):
                    print(f"      来源: {s['quarantine_url']}")

        if alerts["denied_file_access"]:
            print(f"\n  [{len(alerts['denied_file_access'])}] 被拒绝的文件访问:")
            for s in alerts["denied_file_access"][:5]:
                print(f"    - {s['process']} → {s['file']}")
                print(f"      策略: {s['policy_name']} / 决策: {s['policy_decision']}")

        if alerts["xprotect_detections"]:
            print(f"\n  [{len(alerts['xprotect_detections'])}] XProtect 恶意软件检测:")
            for s in alerts["xprotect_detections"]:
                print(f"    - {s['malware']} @ {s['path']}")

        if alerts["gatekeeper_overrides"]:
            print(f"\n  [{len(alerts['gatekeeper_overrides'])}] Gatekeeper 策略覆盖:")
            for s in alerts["gatekeeper_overrides"]:
                print(f"    - {s['process']} → {s['file']}")

        if alerts["auth_failures"]:
            print(f"\n  [{len(alerts['auth_failures'])}] 认证失败:")
            for s in alerts["auth_failures"][:5]:
                print(f"    - {s['description']}")

        print()

    # 高亮事件摘要（最多显示 20 条）
    hl = report["highlights"]
    if hl:
        print(f"── 值得关注的事件 (共 {len(hl)} 条，显示前 20 条) " + "─" * 10)
        for s in hl[:20]:
            sev_tag = f"[{s['severity']}]"
            print(f"  {sev_tag:<10} {s['description']:<30} {s.get('process', '')}")
        print()

    print("=" * 70)
