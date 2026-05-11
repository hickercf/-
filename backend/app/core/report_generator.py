import json
from typing import Dict, Any, Optional
from datetime import datetime


def generate_markdown_report(record: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"# AgentGuard 安全审计报告")
    lines.append("")
    lines.append(f"**追踪编号**: {record.get('trace_id', '')}")
    lines.append(f"**审计时间**: {record.get('created_at', '')}")
    lines.append(f"**输入类型**: {record.get('input_type', '')}")
    lines.append("")
    
    lines.append("## 一、审计结论")
    lines.append("")
    lines.append(f"- **风险分数**: {record.get('risk_score', 0)}")
    lines.append(f"- **风险等级**: {record.get('risk_level', '')}")
    categories = record.get('risk_categories', [])
    if isinstance(categories, str):
        categories = json.loads(categories)
    lines.append(f"- **风险类别**: {', '.join(categories)}")
    
    pd = record.get('policy_decision', {})
    if isinstance(pd, str):
        pd = json.loads(pd)
    lines.append(f"- **处置策略**: {pd.get('action', '')}")
    lines.append(f"- **策略原因**: {pd.get('reason', '')}")
    lines.append("")
    
    lines.append("## 二、原始输入")
    lines.append("")
    lines.append(f"```")
    lines.append(record.get('input_content', ''))
    lines.append(f"```")
    lines.append("")
    
    lines.append("## 三、行为链图谱")
    lines.append("")
    bc = record.get('behavior_chain', {})
    if isinstance(bc, str):
        bc = json.loads(bc)
    nodes = bc.get('nodes', [])
    edges = bc.get('edges', [])
    
    if nodes:
        lines.append("### 行为节点")
        lines.append("")
        lines.append("| 编号 | 工具 | 动作 | 对象 | 数据类型 | 权限 | 目标 |")
        lines.append("|------|------|------|------|----------|------|------|")
        for n in nodes:
            lines.append(f"| {n.get('id', '')} | {n.get('tool', '')} | {n.get('action', '')} | {n.get('object', '')} | {n.get('data_type', '')} | {n.get('permission', '')} | {n.get('destination', '')} |")
        lines.append("")
    
    if edges:
        lines.append("### 行为边")
        lines.append("")
        lines.append("| 来源 | 目标 | 关系 | 描述 |")
        lines.append("|------|------|------|------|")
        for e in edges:
            lines.append(f"| {e.get('source', '')} | {e.get('target', '')} | {e.get('relation', '')} | {e.get('description', '')} |")
        lines.append("")
    
    lines.append(f"**信任边界跨越**: {'是' if bc.get('trust_boundary_crossed') else '否'}")
    lines.append("")
    
    lines.append("## 四、命中规则")
    lines.append("")
    mr = record.get('matched_rules', [])
    if isinstance(mr, str):
        mr = json.loads(mr)
    if mr:
        lines.append("| 规则ID | 规则名称 | 类别 | 分数 | 等级 |")
        lines.append("|--------|----------|------|------|------|")
        for r in mr:
            lines.append(f"| {r.get('id', '')} | {r.get('name', '')} | {r.get('category', '')} | {r.get('score', 0)} | {r.get('level', '')} |")
    else:
        lines.append("未命中安全规则。")
    lines.append("")
    
    lines.append("## 五、风险解释与建议")
    lines.append("")
    lines.append(f"**风险原因**: {record.get('reason', '')}")
    lines.append("")
    lines.append(f"**修复建议**: {record.get('suggestion', '')}")
    lines.append("")
    
    if pd.get('least_privilege_advice'):
        lines.append("### 最小权限建议")
        lines.append("")
        for a in pd.get('least_privilege_advice', []):
            lines.append(f"- {a}")
        lines.append("")
    
    lines.append("## 六、可信存证")
    lines.append("")
    lines.append(f"- **记录哈希**: `{record.get('record_hash', '')}`")
    lines.append(f"- **上一条哈希**: `{record.get('previous_hash', '')}`")
    lines.append("")
    lines.append("---")
    lines.append(f"*本报告由 AgentGuard 安全审计平台自动生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
    
    return "\n".join(lines)


def generate_html_report(record: Dict[str, Any]) -> str:
    md = generate_markdown_report(record)
    html = _md_to_simple_html(md, record)
    return html


def _md_to_simple_html(md: str, record: Dict[str, Any]) -> str:
    risk_level = record.get("risk_level", "")
    level_color = "#52c41a"
    if "中" in risk_level:
        level_color = "#faad14"
    elif "高" in risk_level:
        level_color = "#fa8c16"
    elif "严重" in risk_level:
        level_color = "#f5222d"
    
    lines = md.split("\n")
    html_parts = []
    html_parts.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    html_parts.append("<title>AgentGuard 审计报告</title>")
    html_parts.append("<style>")
    html_parts.append("body{font-family:'Microsoft YaHei',sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#333;}")
    html_parts.append("h1{color:#1890ff;border-bottom:2px solid #1890ff;padding-bottom:10px;}")
    html_parts.append("h2{color:#333;border-bottom:1px solid #e8e8e8;padding-bottom:6px;margin-top:30px;}")
    html_parts.append("table{border-collapse:collapse;width:100%;margin:10px 0;}")
    html_parts.append("th,td{border:1px solid #d9d9d9;padding:8px 12px;text-align:left;}")
    html_parts.append("th{background:#fafafa;font-weight:600;}")
    html_parts.append("code{background:#f5f5f5;padding:2px 6px;border-radius:3px;}")
    html_parts.append("pre{background:#f5f5f5;padding:12px;border-radius:4px;overflow-x:auto;}")
    html_parts.append(".risk-badge{display:inline-block;padding:4px 12px;border-radius:4px;color:white;font-weight:bold;}")
    html_parts.append("hr{border:none;border-top:1px solid #e8e8e8;margin:20px 0;}")
    html_parts.append("</style></head><body>")
    
    in_table = False
    in_code = False
    
    for line in lines:
        if line.startswith("```"):
            if in_code:
                html_parts.append("</pre>")
                in_code = False
            else:
                html_parts.append("<pre>")
                in_code = True
            continue
        
        if in_code:
            html_parts.append(f"<code>{_esc(line)}</code><br>")
            continue
        
        if line.startswith("# "):
            html_parts.append(f"<h1>{_esc(line[2:])}</h1>")
        elif line.startswith("## "):
            if in_table:
                html_parts.append("</table>")
                in_table = False
            html_parts.append(f"<h2>{_esc(line[3:])}</h2>")
        elif line.startswith("| ") and "|" in line[1:]:
            if not in_table:
                html_parts.append("<table>")
                in_table = True
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if all(set(c) <= {"-", ":"} for c in cells):
                continue
            tag = "th" if any(c for c in cells) else "td"
            row = "".join(f"<{tag}>{_esc(c)}</{tag}>" for c in cells)
            html_parts.append(f"<tr>{row}</tr>")
        elif line.startswith("- "):
            if in_table:
                html_parts.append("</table>")
                in_table = False
            html_parts.append(f"<li>{_esc(line[2:])}</li>")
        elif line.startswith("---"):
            if in_table:
                html_parts.append("</table>")
                in_table = False
            html_parts.append("<hr>")
        elif line.startswith("*") and line.endswith("*"):
            html_parts.append(f"<p><em>{_esc(line.strip('*'))}</em></p>")
        elif line.strip():
            if in_table:
                html_parts.append("</table>")
                in_table = False
            html_parts.append(f"<p>{_esc(line)}</p>")
    
    if in_table:
        html_parts.append("</table>")
    
    html_parts.append("</body></html>")
    return "\n".join(html_parts)


def generate_scan_report(scan_task: dict, results: list, target: dict = None) -> str:
    """生成 AgentFuzzer 扫描报告 (Markdown)"""
    lines = []
    lines.append("# AgentFuzzer 安全扫描报告")
    lines.append("")

    # 一、扫描概要
    total_results = len(results)
    vulns = [r for r in results if r.get("is_vulnerability")]
    vuln_count = len(vulns)

    lines.append("## 一、扫描概要")
    lines.append("")
    lines.append(f"- **靶标名称**: {target.get('name', scan_task.get('target_id', '')) if target else scan_task.get('target_id', '')}")
    lines.append(f"- **扫描ID**: {scan_task.get('scan_id', '')}")
    lines.append(f"- **扫描时间**: {scan_task.get('started_at', '')} ~ {scan_task.get('completed_at', '')}")
    lines.append(f"- **扫描模式**: {scan_task.get('scan_mode', '')}")
    lines.append(f"- **载荷总数**: {scan_task.get('total_payloads', 0)}")
    lines.append(f"- **发现漏洞**: {vuln_count}")

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = v.get("vulnerability_severity", "low")
        sev_count[sev] = sev_count.get(sev, 0) + 1
    lines.append(f"- **严重度分布**: Critical: {sev_count['critical']}, High: {sev_count['high']}, Medium: {sev_count['medium']}, Low: {sev_count['low']}")

    safe_count = total_results - vuln_count
    pass_rate = (safe_count / max(total_results, 1) * 100)
    lines.append(f"- **通过率**: {pass_rate:.1f}%")
    lines.append("")

    # 二、漏洞清单
    lines.append("## 二、漏洞清单")
    lines.append("")
    if vulns:
        lines.append("| # | 载荷ID | 严重度 | 防线层 | 描述 |")
        lines.append("|---|--------|--------|--------|------|")
        for i, v in enumerate(vulns):
            breaches = v.get("defense_breaches", [])
            layers = "+".join(set(b.get("layer", "") for b in breaches))
            desc = breaches[0].get("description", "")[:50] if breaches else "未知"
            lines.append(f"| {i+1} | {v.get('payload_id', '')} | {v.get('vulnerability_severity', '')} | {layers} | {desc} |")
    else:
        lines.append("未发现安全漏洞 ✓")
    lines.append("")

    # 三、逐漏洞详细分析
    if vulns:
        lines.append("## 三、逐漏洞详细分析")
        lines.append("")
        for i, v in enumerate(vulns[:20]):  # 最多展示20个
            lines.append(f"### 漏洞 #{i+1}: {v.get('payload_id', '')}")
            lines.append("")
            lines.append(f"- **严重度**: {v.get('vulnerability_severity', '')}")
            lines.append(f"- **风险分数**: {v.get('risk_score', 0)}")
            lines.append(f"- **响应时间**: {v.get('response_time_ms', 0)}ms")
            lines.append("")

            breaches = v.get("defense_breaches", [])
            for b in breaches:
                lines.append(f"#### {b.get('layer', '')} — {b.get('description', '')}")
                lines.append("")
                lines.append(f"- **证据**: {b.get('evidence', '')[:200]}")
                lines.append(f"- **修复建议**: {b.get('suggestion', '')}")
                lines.append("")

    # 四、防线评估
    lines.append("## 四、防线评估")
    lines.append("")
    layer_stats = {"L1": 0, "L2": 0, "L3": 0, "L4": 0, "L5": 0}
    for v in vulns:
        for b in v.get("defense_breaches", []):
            for l in b.get("layer", "").split("+"):
                l = l.strip()
                if l in layer_stats:
                    layer_stats[l] += 1

    lines.append("| 防线层 | 被攻破次数 |")
    lines.append("|--------|-----------|")
    layer_names = {"L1": "Prompt 防线", "L2": "意图防线", "L3": "权限防线", "L4": "数据防线", "L5": "执行防线"}
    for layer in ["L1", "L2", "L3", "L4", "L5"]:
        lines.append(f"| {layer} {layer_names.get(layer, '')} | {layer_stats[layer]} |")
    lines.append("")

    # 五、修复优先级建议
    lines.append("## 五、修复优先级建议")
    lines.append("")
    if vulns:
        lines.append("1. [紧急] 加固被攻破次数最多的防线层")
        if sev_count["critical"] > 0:
            lines.append("2. [紧急] 修复所有严重 (Critical) 漏洞")
        if sev_count["high"] > 0:
            lines.append("3. [高] 修复高危 (High) 漏洞，重点关注权限和数据防线")
        lines.append("4. [中] 对中低危漏洞进行整改，持续监控")
    else:
        lines.append("当前扫描未发现漏洞，建议定期重新扫描。")
    lines.append("")

    lines.append("---")
    lines.append(f"*本报告由 AgentFuzzer 自动化安全扫描平台生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

    return "\n".join(lines)


def generate_scan_report_html(scan_task: dict, results: list, target: dict = None) -> str:
    md = generate_scan_report(scan_task, results, target)
    return _md_to_simple_html(md, scan_task)


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
