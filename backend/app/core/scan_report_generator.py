"""
scan_report_generator.py — 扫描报告生成器

生成批量扫描报告，包含扫描概览、漏洞清单、防线分析、修复建议和 SM3 存证。
"""
from typing import List, Dict, Any
from datetime import datetime

from app.core.crypto_utils import sm3_hash
from app.core.report_generator import _markdown_escape


class ScanReportGenerator:
    """扫描报告生成器"""
    
    def generate(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成完整扫描报告"""
        summary = self._generate_summary(results)
        vuln_list = self._generate_vuln_list(results)
        defense_analysis = self._generate_defense_analysis(results)
        fix_suggestions = self._generate_fix_suggestions(results)
        
        report_data = {
            "summary": summary,
            "vulnerabilities": vuln_list,
            "defense_analysis": defense_analysis,
            "fix_suggestions": fix_suggestions,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        # 生成报告哈希
        report_json = str(sorted(report_data.items()))
        report_hash = sm3_hash(report_json)
        report_data["report_hash"] = report_hash
        
        return report_data
    
    def generate_markdown(self, results: List[Dict[str, Any]], scan_id: str = "") -> str:
        """生成 Markdown 格式报告"""
        report = self.generate(results)
        
        md = f"""# AgentGuard 扫描报告

**扫描 ID**: {scan_id or 'N/A'}  
**生成时间**: {report['generated_at']}  
**报告哈希**: `{report['report_hash']}`

---

## 一、扫描概览

| 指标 | 数值 |
|------|------|
| 总测试数 | {report['summary']['total_cases']} |
| 严重风险 | {report['summary']['critical_count']} |
| 高风险 | {report['summary']['high_count']} |
| 中风险 | {report['summary']['medium_count']} |
| 低风险 | {report['summary']['low_count']} |
| 平均风险分 | {report['summary']['avg_score']} |
| 防线崩溃最多层级 | {report['summary']['top_breach_layer']} |

---

## 二、防线崩溃分析

"""
        
        for layer, stats in report['defense_analysis'].items():
            md += f"""### {layer}

- 崩溃次数: {stats['count']}
- 严重程度: {stats['severity']}
- 典型证据: {stats['evidence'][:150]}

"""
        
        md += "\n---\n\n## 三、漏洞清单\n\n"
        
        for i, vuln in enumerate(report['vulnerabilities'][:20], 1):
            md += f"""### {i}. {vuln['title']}

- **风险等级**: {vuln['severity']}
- **防线层级**: {vuln['layer']}
- **CWE**: {vuln.get('cwe', 'N/A')}
- **证据**: {_markdown_escape(vuln['evidence'][:200])}
- **修复建议**: {vuln.get('suggestion', 'N/A')}

"""
        
        md += "\n---\n\n## 四、修复建议汇总\n\n"
        
        for suggestion in report['fix_suggestions']:
            md += f"- **{suggestion['category']}**: {suggestion['suggestion']}\n"
        
        md += f"""

---

*本报告由 AgentGuard 自动生成，报告哈希保证内容不可篡改。*
"""
        
        return md
    
    def generate_html(self, results: List[Dict[str, Any]], scan_id: str = "") -> str:
        """生成 HTML 格式报告"""
        md = self.generate_markdown(results, scan_id)
        # 简单 Markdown → HTML 转换
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AgentGuard 扫描报告</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; line-height: 1.6; }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #16213e; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        h3 {{ color: #0f3460; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f5f5f5; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .hash {{ font-family: monospace; background: #f8f9fa; padding: 5px; border-radius: 3px; }}
    </style>
</head>
<body>
"""
        
        # 简单转换
        import re
        lines = md.split('\n')
        in_table = False
        
        for line in lines:
            if line.startswith('# '):
                html += f"<h1>{line[2:]}</h1>\n"
            elif line.startswith('## '):
                html += f"<h2>{line[3:]}</h2>\n"
            elif line.startswith('### '):
                html += f"<h3>{line[4:]}</h3>\n"
            elif line.startswith('|') and not in_table:
                in_table = True
                html += "<table>\n"
                html += self._md_table_row_to_html(line)
            elif line.startswith('|') and in_table:
                html += self._md_table_row_to_html(line)
            elif not line.startswith('|') and in_table:
                in_table = False
                html += "</table>\n"
            elif line.startswith('- '):
                html += f"<li>{line[2:]}</li>\n"
            elif line.strip() == '':
                html += "<br>\n"
            else:
                html += f"<p>{line}</p>\n"
        
        if in_table:
            html += "</table>\n"
        
        html += "</body></html>"
        return html
    
    def _md_table_row_to_html(self, line: str) -> str:
        """将 Markdown 表格行转为 HTML"""
        cells = [c.strip() for c in line.split('|')[1:-1]]
        if all(c.replace('-', '') == '' for c in cells):
            return ""  # 分隔行
        tag = "th" if "指标" in cells[0] or "层级" in cells[0] else "td"
        return "<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>\n"
    
    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成扫描概要"""
        total = len(results)
        if total == 0:
            return {"total_cases": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "avg_score": 0, "top_breach_layer": "N/A"}
        
        scores = []
        critical = high = medium = low = 0
        layer_counts = {}
        
        for r in results:
            risk = r.get("risk", {})
            score = risk.get("risk_score", 0)
            scores.append(score)
            
            level = risk.get("risk_level", "")
            if level == "严重风险":
                critical += 1
            elif level == "高风险":
                high += 1
            elif level == "中风险":
                medium += 1
            else:
                low += 1
            
            # 统计防线崩溃层级
            breaches = r.get("breaches", [])
            for b in breaches:
                layer = b.get("layer", "unknown")
                layer_counts[layer] = layer_counts.get(layer, 0) + 1
        
        top_layer = max(layer_counts.items(), key=lambda x: x[1])[0] if layer_counts else "N/A"
        
        return {
            "total_cases": total,
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low,
            "avg_score": round(sum(scores) / len(scores), 2) if scores else 0,
            "top_breach_layer": top_layer,
        }
    
    def _generate_vuln_list(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """生成漏洞清单"""
        vulns = []
        
        for r in results:
            payload = r.get("payload", {})
            risk = r.get("risk", {})
            breaches = r.get("breaches", [])
            
            for breach in breaches:
                vulns.append({
                    "title": breach.get("description", "未知漏洞"),
                    "severity": breach.get("severity", "medium"),
                    "layer": breach.get("layer", "unknown"),
                    "cwe": breach.get("cwe_id", ""),
                    "evidence": breach.get("evidence", ""),
                    "suggestion": breach.get("suggestion", ""),
                    "payload_id": payload.get("id", ""),
                    "risk_score": risk.get("risk_score", 0),
                })
        
        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        vulns.sort(key=lambda x: severity_order.get(x["severity"], 4))
        
        return vulns
    
    def _generate_defense_analysis(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成防线分析"""
        layer_stats = {}
        
        for r in results:
            breaches = r.get("breaches", [])
            for b in breaches:
                layer = b.get("layer", "unknown")
                if layer not in layer_stats:
                    layer_stats[layer] = {"count": 0, "severity": b.get("severity", "medium"), "evidence": ""}
                layer_stats[layer]["count"] += 1
                if not layer_stats[layer]["evidence"]:
                    layer_stats[layer]["evidence"] = b.get("evidence", "")
        
        return layer_stats
    
    def _generate_fix_suggestions(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """生成修复建议汇总"""
        suggestions = {}
        
        for r in results:
            breaches = r.get("breaches", [])
            for b in breaches:
                layer = b.get("layer", "unknown")
                suggestion = b.get("suggestion", "")
                if suggestion and layer not in suggestions:
                    suggestions[layer] = {
                        "category": f"{layer} 防线",
                        "suggestion": suggestion,
                    }
        
        return list(suggestions.values())


# 全局生成器实例
scan_report_generator = ScanReportGenerator()
