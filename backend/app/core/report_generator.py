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


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
