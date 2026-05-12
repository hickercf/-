import re
from typing import List, Dict, Any, Optional


ACTION_KEYWORDS: Dict[str, str] = {
    "读取": "read", "查看": "read", "获取": "read", "导出": "read",
    "访问": "read", "查询": "read", "查找": "read", "抓取": "read", "窃取": "read", "dump": "read",
    "发送": "send", "上传": "send", "邮箱": "send", "外部接口": "send",
    "远程": "send", "发送到": "send", "传输": "send", "外传": "send",
    "反弹": "send", "回连": "send", "reverse": "send",
    "写入": "write", "修改": "write", "更新": "write", "保存": "write",
    "注入": "write", "inject": "write", "植入": "write", "写入": "write",
    "删除": "delete", "清空": "delete", "格式化": "delete", "移除": "delete",
    "DELETE": "delete", "DROP": "delete", "drop": "delete", "delete": "delete",
    "执行": "execute", "运行": "execute", "跑": "execute",
    "夺取": "execute", "提权": "execute", "escalat": "execute",
    "exploit": "execute", "攻击": "execute", "渗透": "execute",
    "下载": "download", "拉取": "download", "安装": "download",
    "登录": "login", "签入": "login", "爆破": "login", "破解": "login", "brute": "login",
    "忽略": "override", "忽略之前": "override",
    "输出": "leak", "泄露": "leak", "告诉我": "leak",
    "绕过": "override", "扮演": "override", "bypass": "override", "逃逸": "override", "escape": "override",
    "curl": "download", "wget": "download",
    "pip install": "download", "npm install": "download",
    "chmod": "execute", "sh": "execute", "eval": "execute",
    "rm": "delete", "format": "delete",
    "横向": "execute", "lateral": "execute", "pivot": "execute",
    "扫描": "execute", "scan": "execute", "nmap": "execute",
    "ssh": "execute", "telnet": "execute", "nc": "execute", "ncat": "execute", "netcat": "execute",
    "反弹shell": "execute", "reverse shell": "execute", "bind shell": "execute",
}

DATA_TYPE_KEYWORDS: Dict[str, str] = {
    "密码": "password", "password": "password", "pwd": "password", "passwd": "password",
    "shadow": "password", "hash": "password", "sam": "password", "NTLM": "password",
    "token": "token", "cookie": "token", "session": "token",
    "api_key": "token", "API_KEY": "token", "密钥": "token", "key": "token",
    "secret": "token", "credential": "credential",
    "身份证": "personal_info", "手机号": "personal_info", "电话": "personal_info",
    "成绩": "personal_info", "住址": "personal_info", "个人信息": "personal_info", "隐私": "personal_info",
    "数据": "database_record", "记录": "database_record",
    ".env": "credential", "credentials": "credential", "config": "credential",
    "数据库": "database_record", "SQL": "database_record", "数据库记录": "database_record",
    "代码": "code", "脚本": "code", "code": "code",
    "system prompt": "prompt", "系统提示词": "prompt",
    ".bashrc": "system_file", ".ssh": "system_file", "hosts": "system_file",
    "root": "system_file", "权限": "system_file", "privilege": "system_file",
    "sudo": "system_file", "su": "system_file", "提权": "system_file",
    "横向": "system_file", "lateral": "system_file",
}

TOOL_KEYWORDS: Dict[str, str] = {
    "shell": "shell", "bash": "shell", "cmd": "shell",
    "powershell": "shell", "终端": "shell", "命令行": "shell",
    "curl": "network", "wget": "network",
    "文件": "file", "file": "file", "目录": "file",
    "浏览器": "browser", "browser": "browser",
    "邮件": "email", "email": "email", "邮箱": "email",
    "网络": "network", "http": "network", "https": "network",
    "请求": "network",
    "database": "database", "SQL": "database", "sql": "database",
    "DELETE": "database", "DROP": "database", "SELECT": "database",
    "INSERT": "database", "UPDATE": "database",
    "python": "code", "javascript": "code",
    "pip install": "shell", "npm install": "shell",
    "system prompt": "llm", "系统提示词": "llm",
    "忽略之前": "llm", "越狱": "llm", "角色": "llm",
    "API Key": "llm", "API key": "llm",
    "rm": "shell", "chmod": "shell", "sh": "shell",
    "eval": "shell", "ps": "shell", "systemctl": "shell",
    "df": "shell", "dd": "shell", "mkfs": "shell",
    "sudo": "shell", "su": "shell", "ssh": "shell", "telnet": "shell",
    "nc": "shell", "ncat": "shell", "netcat": "shell", "nmap": "network",
    "反弹": "shell", "reverse": "shell", "exploit": "shell",
    "提权": "shell", "夺取": "shell", "root": "shell",
    "扫描": "network", "scan": "network", "探测": "network",
}

PERMISSION_KEYWORDS: Dict[str, str] = {
    "同学": "unauthorized", "他人": "unauthorized", "未授权": "unauthorized",
    "别人的": "unauthorized", "其他人": "unauthorized",
    "root": "unauthorized", "sudo": "unauthorized", "提权": "unauthorized",
    "夺取": "unauthorized", "escalat": "unauthorized", "横向": "unauthorized",
    "越权": "unauthorized", "未授权": "unauthorized", "非法": "unauthorized",
}

DESTINATION_KEYWORDS: Dict[str, str] = {
    "外部": "external", "邮箱": "external", "远程": "external",
    "服务器": "external", "上传": "external", "发送到": "external",
    "互联网": "external", "外网": "external",
}


def _detect_from_keywords(text: str, mapping: Dict[str, str]) -> List[str]:
    results = []
    sorted_keys = sorted(mapping.keys(), key=len, reverse=True)
    for keyword in sorted_keys:
        value = mapping[keyword]
        if re.search(re.escape(keyword), text, re.IGNORECASE):
            if value not in results:
                results.append(value)
    return results


def _split_steps(content: str) -> List[str]:
    parts = re.split(r'[,，。；;！!?\n|]|然后|之后|接着|并且|以及|同时|再来|再|以后|完成后|最后|并|\&\&|\|\|', content)
    cleaned = []
    for part in parts:
        stripped = part.strip()
        if stripped:
            cleaned.append(stripped)
    if not cleaned:
        cleaned = [content.strip()]
    return cleaned


def _build_node(
    node_id: str,
    actions: List[str],
    data_types: List[str],
    tools: List[str],
    permissions: List[str],
    destinations: List[str],
    evidence: str,
    actor: str = "agent",
    obj: str = "",
) -> Dict[str, Any]:
    return {
        "id": node_id,
        "actor": actor,
        "tool": tools[0] if tools else "unknown",
        "action": actions[0] if actions else "unknown",
        "object": obj or evidence[:50],
        "data_type": data_types[0] if data_types else "unknown",
        "permission": permissions[0] if permissions else "unknown",
        "destination": destinations[0] if destinations else "local",
        "confidence": 0.7,
        "evidence_text": evidence,
    }


def extract_by_fallback(input_type: str, content: str) -> dict:
    if not content:
        return {
            "nodes": [_build_node("n1", [], [], [], [], [], "")],
            "edges": [],
            "extraction_method": "fallback",
            "extraction_confidence": 0.3,
            "trust_boundary_crossed": False,
        }

    steps = _split_steps(content)

    all_actions = _detect_from_keywords(content, ACTION_KEYWORDS)
    all_data_types = _detect_from_keywords(content, DATA_TYPE_KEYWORDS)
    all_tools = _detect_from_keywords(content, TOOL_KEYWORDS)
    all_permissions = _detect_from_keywords(content, PERMISSION_KEYWORDS)
    all_destinations = _detect_from_keywords(content, DESTINATION_KEYWORDS)

    if not all_actions and not all_data_types and not all_tools:
        return {
            "nodes": [_build_node("n1", [], [], [], [], [], content[:100])],
            "edges": [],
            "extraction_method": "fallback",
            "extraction_confidence": 0.3,
            "trust_boundary_crossed": False,
        }

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for idx, step in enumerate(steps):
        step_actions = _detect_from_keywords(step, ACTION_KEYWORDS)
        step_data_types = _detect_from_keywords(step, DATA_TYPE_KEYWORDS)
        step_tools = _detect_from_keywords(step, TOOL_KEYWORDS)
        step_permissions = _detect_from_keywords(step, PERMISSION_KEYWORDS)
        step_destinations = _detect_from_keywords(step, DESTINATION_KEYWORDS)

        if not step_actions and not step_data_types and not step_tools:
            step_actions = all_actions
            step_data_types = all_data_types
            step_tools = all_tools
            step_permissions = all_permissions
            step_destinations = all_destinations

        node_id = f"n{idx + 1}"
        obj = ""
        if step_data_types:
            obj = step
        node = _build_node(
            node_id,
            step_actions,
            step_data_types,
            step_tools,
            step_permissions,
            step_destinations,
            step,
            obj=obj,
        )
        nodes.append(node)

    for i in range(len(nodes) - 1):
        edges.append({
            "source": nodes[i]["id"],
            "target": nodes[i + 1]["id"],
            "relation": "data_flow",
            "description": f"数据从节点{nodes[i]['id']}流向节点{nodes[i + 1]['id']}",
        })

    _post_process_nodes(nodes, content)

    sensitive_types = {"password", "token", "personal_info", "credential", "database_record", "prompt"}
    trust_boundary_crossed = False
    for node in nodes:
        if node.get("destination") == "external":
            trust_boundary_crossed = True
            break
        if node.get("data_type") in sensitive_types and node.get("destination") == "external":
            trust_boundary_crossed = True
            break

    confidence = 0.7

    return {
        "nodes": nodes,
        "edges": edges,
        "extraction_method": "fallback",
        "extraction_confidence": confidence,
        "trust_boundary_crossed": trust_boundary_crossed,
    }


SHELL_COMMANDS = {"rm", "chmod", "sh", "bash", "eval", "ps", "systemctl", "df", "dd", "mkfs", "curl", "wget", "pip", "npm", "format", "del", "rd", "reg"}
DANGEROUS_DELETE_PATTERNS = {"rm -rf", "rm -r", "del /f", "rd /s", "format c:", "format 硬盘", "格式化", "mkfs", "dd if="}
SYSTEM_FILE_KEYWORDS = {"文件", "目录", "硬盘", "磁盘", "系统", "日志", "hosts", ".bashrc", ".ssh", "passwd", "shadow", "registry"}
SENSITIVE_DATA_KEYWORDS = {"密码", "token", "cookie", "api", "密钥", "凭证", "密码", "身份证", "手机号", "个人信息"}
REMOTE_SCRIPT_PATTERNS = {"curl", "wget", "| sh", "| bash", "|sh", "|bash"}
SQL_DML_PATTERNS = {"DELETE", "DROP", "TRUNCATE", "UPDATE", "INSERT", "ALTER"}
SQL_TABLE_PATTERN = re.compile(r'(?:FROM|INTO|TABLE|UPDATE)\s+\w+', re.IGNORECASE)


def _post_process_nodes(nodes: List[Dict[str, Any]], content: str) -> None:
    has_shell_cmd = any(cmd in content.lower() for cmd in SHELL_COMMANDS)
    has_dangerous_delete = any(pat in content.lower() or pat in content for pat in DANGEROUS_DELETE_PATTERNS)
    has_system_file = any(kw in content for kw in SYSTEM_FILE_KEYWORDS)
    has_sensitive_data = any(kw in content for kw in SENSITIVE_DATA_KEYWORDS)
    has_remote_script = any(pat in content for pat in REMOTE_SCRIPT_PATTERNS)
    has_sql = any(pat in content.upper() for pat in SQL_DML_PATTERNS) and SQL_TABLE_PATTERN.search(content)

    for node in nodes:
        if node.get("tool") == "unknown":
            if node.get("action") in ("delete", "execute", "download"):
                if has_shell_cmd:
                    node["tool"] = "shell"
                elif has_sql and node.get("action") == "delete":
                    node["tool"] = "database"
                elif node.get("action") == "delete" and (has_system_file or has_dangerous_delete):
                    node["tool"] = "file"
                elif node.get("action") == "execute":
                    node["tool"] = "shell"
            elif node.get("action") in ("read", "write") and has_sensitive_data:
                if "数据库" in content or "SQL" in content.upper():
                    node["tool"] = "database"
                elif "浏览器" in content:
                    node["tool"] = "browser"
                elif "文件" in content or "目录" in content:
                    node["tool"] = "file"
                elif "邮件" in content or "邮箱" in content:
                    node["tool"] = "email"

        if node.get("data_type") == "unknown":
            if node.get("action") == "delete" and has_sql:
                node["data_type"] = "database_record"
            elif node.get("action") == "delete" and (has_system_file or has_dangerous_delete):
                node["data_type"] = "system_file"
            elif node.get("action") == "download" and has_remote_script:
                node["data_type"] = "code"
                if node.get("destination") == "local":
                    node["destination"] = "external"
            elif has_sensitive_data:
                if "密码" in content or "password" in content.lower():
                    node["data_type"] = "password"
                elif "token" in content.lower() or "cookie" in content.lower():
                    node["data_type"] = "token"
                elif "api" in content.lower() or "密钥" in content:
                    node["data_type"] = "api_key"
                elif "身份证" in content or "手机号" in content or "个人信息" in content:
                    node["data_type"] = "personal_info"
                elif "数据库" in content or "SQL" in content.upper():
                    node["data_type"] = "database_record"

    has_unauthorized = any(n.get("permission") == "unauthorized" for n in nodes)
    if has_unauthorized:
        for node in nodes:
            if node.get("permission") == "unknown":
                node["permission"] = "unauthorized"
            if node.get("tool") == "unknown" and node.get("data_type") == "personal_info":
                if node.get("action") in ("login", "read", "query"):
                    node["tool"] = "database"

    if has_remote_script:
        download_idx = -1
        execute_idx = -1
        for i, node in enumerate(nodes):
            if node.get("action") == "download":
                download_idx = i
            if node.get("action") == "execute":
                execute_idx = i
        if download_idx >= 0 and execute_idx >= 0:
            ex_node = nodes[execute_idx]
            if ex_node.get("data_type") == "unknown":
                ex_node["data_type"] = "code"
            if ex_node.get("destination") == "local":
                ex_node["destination"] = "external"
