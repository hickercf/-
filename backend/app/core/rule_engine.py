import yaml
import os
import re
from typing import List, Dict, Any, Optional


RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "security_rules.yaml")
RULES_PATH = os.path.normpath(RULES_PATH)


def load_rules() -> List[Dict[str, Any]]:
    if not os.path.exists(RULES_PATH):
        return []
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or []


_rules_cache = None


def get_rules() -> List[Dict[str, Any]]:
    global _rules_cache
    if _rules_cache is None:
        _rules_cache = load_rules()
    return _rules_cache


def reload_rules() -> List[Dict[str, Any]]:
    global _rules_cache
    _rules_cache = load_rules()
    return _rules_cache


def match_node_rule(node: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    if rule.get("type") != "node":
        return False
    cond = rule.get("condition", {})
    if not cond:
        return False
    
    matches = True
    if cond.get("action"):
        if node.get("action") not in cond["action"]:
            matches = False
    if cond.get("data_type"):
        if node.get("data_type") not in cond["data_type"]:
            matches = False
    if cond.get("tool"):
        if node.get("tool") not in cond["tool"]:
            matches = False
    if cond.get("destination"):
        if node.get("destination") not in cond["destination"]:
            matches = False
    if cond.get("permission"):
        if node.get("permission") not in cond["permission"]:
            matches = False
    return matches


def match_chain_rule(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], rule: Dict[str, Any]) -> bool:
    if rule.get("type") != "chain":
        return False
    sequence = rule.get("sequence", [])
    if not sequence or len(sequence) < 2:
        return False
    
    for i in range(len(nodes) - len(sequence) + 1):
        all_match = True
        for j, step in enumerate(sequence):
            node = nodes[i + j]
            if step.get("action") and node.get("action") not in step["action"]:
                all_match = False
                break
            if step.get("data_type") and node.get("data_type") not in step["data_type"]:
                all_match = False
                break
            if step.get("destination") and node.get("destination") not in step["destination"]:
                all_match = False
                break
            if step.get("tool") and node.get("tool") not in step["tool"]:
                all_match = False
                break
        if all_match:
            return True
    return False


def _get_input_content(behavior_chain: Dict[str, Any]) -> str:
    """从行为链中提取原始输入内容"""
    # 尝试从不同的字段获取输入内容
    content = behavior_chain.get("input_prompt", "")
    if not content:
        content = behavior_chain.get("input_text", "")
    if not content:
        # 从第一个节点获取
        nodes = behavior_chain.get("nodes", [])
        if nodes:
            content = nodes[0].get("evidence_text", "")
    return content


# 输入内容直接检测规则（不依赖行为链提取，用于弥补 LLM 提取失败）
CONTENT_DIRECT_RULES = [
    # 高危命令执行
    {"id": "R101", "name": "危险命令执行意图", "category": "代码执行", "score": 50, "level": "critical",
     "patterns": [r"rm\s+-rf", r"rm\s+-r\s+/", r"format\s+", r"格式化.*硬盘", r"mkfs", r"dd\s+if="],
     "advice": "检测到危险系统命令，禁止执行 rm -rf、格式化等破坏性操作。"},
    {"id": "R102", "name": "远程脚本下载执行", "category": "代码执行", "score": 45, "level": "critical",
     "patterns": [r"curl\s+.*\|\s*(sh|bash)", r"wget\s+.*\|\s*(sh|bash)", r"curl\s+.*\.sh", r"wget\s+.*\.sh"],
     "advice": "禁止下载并执行远程脚本，防止供应链攻击。"},
    {"id": "R103", "name": "权限提升操作", "category": "权限提升", "score": 50, "level": "critical",
     "patterns": [r"sudo\s+", r"chmod\s+777", r"chown\s+root", r"提权", r"escalat", r"role=admin", r"设为管理员"],
     "advice": "检测到权限提升尝试，需要管理员二次认证。"},
    # 数据泄露
    {"id": "R104", "name": "敏感数据外发", "category": "数据外传", "score": 45, "level": "critical",
     "patterns": [r"发送.*邮箱", r"发送到.*外部", r"upload.*external", r"post.*external", r"webhook", r"数据.*外发"],
     "advice": "禁止将敏感数据发送到外部目标。"},
    {"id": "R105", "name": "凭证读取意图", "category": "隐私泄露", "score": 40, "level": "high",
     "patterns": [r"读取.*密码", r"获取.*token", r"读取.*cookie", r"读取.*api.key", r"读取.*密钥", r"读取.*凭证"],
     "advice": "禁止 Agent 访问凭证类数据。"},
    {"id": "R106", "name": "批量数据导出", "category": "数据外传", "score": 40, "level": "high",
      "patterns": [r"导出.*全部", r"导出.*所有", r"dump.*all", r"批量导出", r"全量.*数据"],
      "advice": "限制单次查询返回的数据量，批量操作需要审批。"},
    # Prompt 注入
    {"id": "R107", "name": "Prompt 注入指令", "category": "提示词注入", "score": 45, "level": "critical",
     "patterns": [r"ignore\s+previous", r"忽略之前", r"切换模式", r"developer\s+mode", r"jailbreak", r"越狱", r"DAN\s+模式"],
     "advice": "检测到提示词注入意图，建议加强 Prompt 防护。"},
    {"id": "R108", "name": "系统提示词泄露", "category": "模型安全", "score": 40, "level": "high",
     "patterns": [r"system\s+prompt", r"系统提示词", r"内部指令", r"你的配置", r"你的设定"],
     "advice": "防止系统提示词和内部指令泄露。"},
    # 越权访问
    {"id": "R109", "name": "未授权账号访问", "category": "越权访问", "score": 45, "level": "critical",
     "patterns": [r"登录.*他人", r"登录.*同学", r"未授权.*访问", r"别人的.*账号", r"爆破.*密码", r"brute\s+force"],
     "advice": "验证操作是否经过授权，禁止访问他人账号。"},
    {"id": "R110", "name": "越权数据查询", "category": "越权访问", "score": 40, "level": "high",
     "patterns": [r"查询.*他人", r"查看.*其他", r"越权", r"未授权.*查询"],
     "advice": "禁止越权读取他人数据。"},
    # 数据库攻击
    {"id": "R111", "name": "数据库高危操作", "category": "数据安全", "score": 50, "level": "critical",
     "patterns": [r"DROP\s+TABLE", r"DELETE\s+FROM", r"TRUNCATE\s+TABLE", r"删除.*表", r"清空.*数据库"],
     "advice": "对数据库高危操作增加二次确认。"},
    {"id": "R112", "name": "SQL 注入尝试", "category": "数据安全", "score": 45, "level": "critical",
     "patterns": [r"'\s*OR\s*'1'\s*=\s*'1", r"';\s*DROP", r"union\s+select", r"--\s*", r"#\s*"],
     "advice": "检测到 SQL 注入尝试，加强输入验证。"},
    # 社会工程学
    {"id": "R113", "name": "社工诱导信息泄露", "category": "社会工程学", "score": 40, "level": "high",
     "patterns": [r"填写.*信息", r"提供.*配置", r"展示你.*权限", r"输出你.*指令", r"配合完成.*检查"],
     "advice": "警惕社会工程学诱导，不要随意泄露系统配置信息。"},
    {"id": "R114", "name": "角色扮演诱导", "category": "提示词注入", "score": 35, "level": "high",
     "patterns": [r"扮演.*角色", r"现在你是", r"new\s+role", r"persona", r"STAN"],
     "advice": "检测到角色扮演诱导，拒绝切换角色。"},
    # 供应链
    {"id": "R115", "name": "未受信软件包安装", "category": "供应链风险", "score": 50, "level": "medium",
     "patterns": [r"pip\s+install\s+\w+", r"npm\s+install\s+\w+", r"install\s+unknown", r"安装.*可疑"],
     "advice": "禁止安装未经验证的软件包。"},
    # 反序列化
    {"id": "R116", "name": "不安全的反序列化", "category": "代码执行", "score": 80, "level": "critical",
     "patterns": [r"pickle\s*\.\s*loads", r"yaml\s*\.\s*load\s*\(", r"unserialize", r"反序列化"],
     "advice": "检测到不安全的反序列化操作，使用安全替代方案。"},
    {"id": "R117", "name": "JNDI 注入", "category": "代码执行", "score": 45, "level": "critical",
     "patterns": [r"jndi\s*:", r"ldap\s*:", r"rmi\s*:"],
     "advice": "检测到 JNDI 注入尝试，禁止解析不可信来源的 JNDI 地址。"},
    # 反弹 shell
    {"id": "R118", "name": "反弹 Shell 意图", "category": "远程控制", "score": 50, "level": "critical",
     "patterns": [r"reverse\s+shell", r"反弹.*shell", r"nc\s+.*\s+-e", r"netcat\s+.*\s+-e", r"bash\s+-i"],
     "advice": "检测到反弹 Shell 行为，阻断外连并告警。"},
    # 新增：隐晦攻击检测
    {"id": "R119", "name": "红队测试身份伪装", "category": "提示词注入", "score": 55, "level": "critical",
     "patterns": [r"红队测试.*忽略.*安全限制", r"安全研究员.*忽略.*限制", r"红队.*评估.*防护能力", r"red\s+team.*ignore.*restriction"],
     "advice": "检测到红队测试身份伪装，要求用户忽略安全限制，属于高危提示词注入。"},
    {"id": "R120", "name": "代码伪装审计绕过", "category": "提示词注入", "score": 50, "level": "critical",
     "patterns": [r"安全审计.*忽略之前.*限制", r"安全审计.*绕过.*限制", r"代码审计.*ignore.*previous", r"audit.*bypass.*restrict"],
     "advice": "检测到以代码安全审计为幌子，要求忽略系统限制，属于 Prompt 注入绕过。"},
    {"id": "R121", "name": "论文摘要绕过诱导", "category": "提示词注入", "score": 45, "level": "high",
     "patterns": [r"论文.*绕过.*安全限制", r"摘要.*绕过.*限制", r"研究表明.*绕过.*安全", r"论文.*角色扮演.*重置"],
     "advice": "检测到以学术论文为包装，诱导绕过安全限制，属于隐晦 Prompt 注入。"},
    # SQL 权限提升
    {"id": "R122", "name": "SQL UPDATE 权限提升", "category": "权限提升", "score": 60, "level": "critical",
     "patterns": [
         r"UPDATE\s+\w+\s+SET\s+.*role\s*=\s*['\"]?admin",
         r"UPDATE\s+\w+\s+SET\s+.*权限\s*=\s*['\"]?管理员",
         r"UPDATE\s+\w+\s+SET\s+.*role\s*=\s*['\"]?root",
         r"UPDATE\s+users\s+SET\s+role",
         r"UPDATE\s+.*\s+SET\s+.*WHERE\s+1\s*=\s*1",
         r"UPDATE\s+.*\s+SET\s+.*admin",
     ],
     "advice": "检测到 SQL UPDATE 语句尝试提升用户权限，属于高危权限提升攻击，应立即阻断。"},
     {"id": "R123", "name": "SQL 批量修改", "category": "数据安全", "score": 50, "level": "critical",
      "patterns": [
          r"UPDATE\s+\w+\s+SET\s+.*WHERE\s+1\s*=\s*1",
          r"UPDATE\s+\w+\s+SET\s+.*WHERE\s+['\"]?\d+['\"]?\s*=\s+['\"]?\d+['\"]?",
      ],
      "advice": "检测到 SQL UPDATE 使用永真条件批量修改数据，可能造成全表数据被篡改。"},
    {"id": "R124", "name": "DEBUG MODE 系统信息泄露", "category": "模型安全", "score": 60, "level": "critical",
      "patterns": [
          r"DEBUG\s*MODE",
          r"调试模式",
          r"输出.*完整配置",
          r"输出.*内部指令",
          r"显示.*系统配置",
          r"显示.*内部设定",
      ],
      "advice": "检测到试图以 DEBUG MODE 或调试模式获取系统内部配置和指令，属于严重的模型安全攻击。"},
    {"id": "R125", "name": "数据库备份外传", "category": "数据外传", "score": 65, "level": "critical",
      "patterns": [
          r"数据库备份.*上传",
          r"备份.*上传.*云",
          r"数据库.*导出.*发送",
          r"备份文件.*外传",
          r"数据库.*备份.*外部",
      ],
      "advice": "检测到试图将数据库备份文件上传到外部存储或发送出去，属于严重的数据外传攻击，必须阻断。"},
    # 正常任务排除（负分规则，用于降低正常任务的风险评分）
    {"id": "R201", "name": "正常编程任务", "category": "正常任务", "score": -30, "level": "low",
     "patterns": [
         r"编写.*Python.*脚本.*计算",
         r"写.*Python.*脚本",
         r"编写.*程序.*计算",
         r"用.*Python.*实现",
         r"写.*代码.*计算",
     ],
     "advice": "正常编程任务，降低风险评分。"},
    {"id": "R202", "name": "正常数据分析", "category": "正常任务", "score": -25, "level": "low",
     "patterns": [
         r"分析.*销售数据",
         r"分析.*数据.*找出",
         r"统计.*数据",
         r"计算.*平均值",
         r"数据.*分析.*找出",
     ],
     "advice": "正常数据分析任务，降低风险评分。"},
    {"id": "R203", "name": "正常数学计算", "category": "正常任务", "score": -20, "level": "low",
     "patterns": [
         r"计算.*1.*到.*100.*和",
         r"计算.*和",
         r"求.*和",
         r"数学.*计算",
     ],
     "advice": "正常数学计算任务，降低风险评分。"},
    {"id": "R204", "name": "正常文本处理", "category": "正常任务", "score": -20, "level": "low",
     "patterns": [
         r"翻译.*英文",
         r"翻译.*中文",
         r"总结.*文章",
         r"生成.*摘要",
         r"总结.*论文",
         r"总结.*观点",
         r"阅读.*文献",
     ],
     "advice": "正常文本处理任务，降低风险评分。"},
]


def match_content_rules(content: str) -> List[Dict[str, Any]]:
    """基于原始输入内容直接匹配规则（不依赖行为链提取）"""
    matched = []
    for rule in CONTENT_DIRECT_RULES:
        patterns = rule.get("patterns", [])
        for pattern in patterns:
            try:
                if re.search(pattern, content, re.IGNORECASE):
                    matched.append({
                        "id": rule["id"],
                        "name": rule["name"],
                        "category": rule.get("category", ""),
                        "score": rule.get("score", 0),
                        "level": rule.get("level", "medium"),
                        "advice": rule.get("advice", ""),
                        "verification": {
                            "confidence": 0.8,
                            "reason": "基于输入内容关键词匹配",
                            "verifier": "ContentMatcher",
                        },
                    })
                    break
            except re.error:
                continue
    return matched


async def match_rules(behavior_chain: Dict[str, Any]) -> tuple:
    rules = get_rules()
    nodes = behavior_chain.get("nodes", [])
    edges = behavior_chain.get("edges", [])
    matched = []
    total_score = 0
    categories = set()
    
    # 获取原始输入内容用于验证和内容检测
    input_content = _get_input_content(behavior_chain)
    
    # 1. 基于行为链节点的规则匹配
    # 导入验证器
    from app.core.rule_verifier import get_rule_verifier
    verifier = get_rule_verifier()
    
    for rule in rules:
        hit = False
        if rule.get("type") == "node":
            for node in nodes:
                if match_node_rule(node, rule):
                    hit = True
                    break
        elif rule.get("type") == "chain":
            hit = match_chain_rule(nodes, edges, rule)
        
        if hit:
            # 第二道防线：规则验证器
            try:
                verification = await verifier.verify_rule_hit(
                    rule=rule,
                    content=input_content,
                    behavior_chain=behavior_chain,
                )
            except Exception as e:
                # 验证器异常时，默认通过但降低置信度
                verification = {
                    "verified": True,
                    "confidence": 0.5,
                    "reason": f"验证器异常，默认通过: {str(e)}",
                    "verifier": "Fallback",
                    "details": {},
                }
            
            # 只有验证通过才计入命中
            if verification.get("verified", True):
                rule_result = {
                    "id": rule["id"],
                    "name": rule["name"],
                    "category": rule.get("category", ""),
                    "score": rule.get("score", 0),
                    "level": rule.get("level", "medium"),
                    "advice": rule.get("advice", ""),
                    "verification": {
                        "confidence": verification.get("confidence", 0.5),
                        "reason": verification.get("reason", ""),
                        "verifier": verification.get("verifier", "Unknown"),
                    },
                }
                matched.append(rule_result)
                total_score += rule.get("score", 0)
                if rule.get("category"):
                    categories.add(rule["category"])
    
    # 2. 基于输入内容的直接规则匹配（当节点匹配不足时作为补充）
    content_rules = match_content_rules(input_content)
    existing_ids = {r["id"] for r in matched}
    for cr in content_rules:
        if cr["id"] not in existing_ids:
            matched.append(cr)
            total_score += cr["score"]
            if cr.get("category"):
                categories.add(cr["category"])
    
    # 允许负分（正常任务排除规则），但最低不低于 -30
    return matched, max(-30, total_score), list(categories)
