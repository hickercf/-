from typing import Dict, Any, List
from datetime import datetime
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import json
import os

# 注册中文字体
def _register_fonts():
    """注册中文字体，尝试多个路径"""
    font_paths = [
        # Windows 系统字体
        "C:/Windows/Fonts/simhei.ttf",
        "C:/Windows/Fonts/simsun.ttc",
        "C:/Windows/Fonts/msyh.ttc",
        # Linux 系统字体
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        # macOS 系统字体
        "/System/Library/Fonts/PingFang.ttc",
        "/Library/Fonts/Arial Unicode.ttf",
    ]
    
    for font_path in font_paths:
        if os.path.exists(font_path):
            try:
                if font_path.endswith('.ttc'):
                    pdfmetrics.registerFont(TTFont('ChineseFont', font_path, subfontIndex=0))
                else:
                    pdfmetrics.registerFont(TTFont('ChineseFont', font_path))
                return True
            except Exception:
                continue
    return False


# 尝试注册字体
FONT_REGISTERED = _register_fonts()


def _create_styles():
    """创建PDF样式"""
    styles = getSampleStyleSheet()
    
    # 基础字体名称
    base_font = 'ChineseFont' if FONT_REGISTERED else 'Helvetica'
    
    # 标题样式
    styles.add(ParagraphStyle(
        name='CustomTitle',
        fontName=base_font,
        fontSize=24,
        leading=30,
        alignment=TA_CENTER,
        spaceAfter=30,
        textColor=colors.HexColor('#1a1a2e'),
    ))
    
    # 副标题样式
    styles.add(ParagraphStyle(
        name='CustomSubtitle',
        fontName=base_font,
        fontSize=14,
        leading=18,
        alignment=TA_CENTER,
        spaceAfter=20,
        textColor=colors.HexColor('#666666'),
    ))
    
    # 章节标题样式
    styles.add(ParagraphStyle(
        name='SectionTitle',
        fontName=base_font,
        fontSize=16,
        leading=20,
        spaceBefore=20,
        spaceAfter=12,
        textColor=colors.HexColor('#1890ff'),
        borderColor=colors.HexColor('#1890ff'),
        borderWidth=2,
        borderPadding=5,
        leftIndent=0,
    ))
    
    # 正文样式
    styles.add(ParagraphStyle(
        name='CustomBody',
        fontName=base_font,
        fontSize=10,
        leading=14,
        spaceBefore=6,
        spaceAfter=6,
        textColor=colors.HexColor('#333333'),
    ))
    
    # 风险等级样式
    styles.add(ParagraphStyle(
        name='RiskCritical',
        fontName=base_font,
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#ff4d4f'),
        backColor=colors.HexColor('#fff1f0'),
        borderPadding=8,
        spaceBefore=8,
        spaceAfter=8,
    ))
    
    styles.add(ParagraphStyle(
        name='RiskHigh',
        fontName=base_font,
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#ff7a45'),
        backColor=colors.HexColor('#fff7e6'),
        borderPadding=8,
        spaceBefore=8,
        spaceAfter=8,
    ))
    
    styles.add(ParagraphStyle(
        name='RiskMedium',
        fontName=base_font,
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#faad14'),
        backColor=colors.HexColor('#fffbe6'),
        borderPadding=8,
        spaceBefore=8,
        spaceAfter=8,
    ))
    
    styles.add(ParagraphStyle(
        name='RiskLow',
        fontName=base_font,
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#52c41a'),
        backColor=colors.HexColor('#f6ffed'),
        borderPadding=8,
        spaceBefore=8,
        spaceAfter=8,
    ))
    
    return styles


def generate_pdf_report(record: Dict[str, Any]) -> bytes:
    """生成PDF格式的安全审计报告"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=18,
    )
    
    styles = _create_styles()
    story = []
    
    # 报告标题
    story.append(Paragraph("AgentFuzzer 安全审计报告", styles['CustomTitle']))
    story.append(Paragraph(f"追踪编号: {record.get('trace_id', 'N/A')}", styles['CustomSubtitle']))
    story.append(Spacer(1, 0.2*inch))
    
    # 基本信息表格
    basic_data = [
        ['审计时间', record.get('created_at', 'N/A')],
        ['输入类型', record.get('input_type', 'N/A')],
        ['风险分数', str(record.get('risk_score', 0))],
        ['风险等级', record.get('risk_level', 'N/A')],
    ]
    
    pd = record.get('policy_decision', {})
    if isinstance(pd, str):
        try:
            pd = json.loads(pd)
        except:
            pd = {}
    
    basic_data.append(['处置策略', pd.get('action', 'N/A').upper()])
    
    basic_table = Table(basic_data, colWidths=[2*inch, 4*inch])
    basic_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#333333')),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'ChineseFont' if FONT_REGISTERED else 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d9d9d9')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(basic_table)
    story.append(Spacer(1, 0.3*inch))
    
    # 风险等级展示
    story.append(Paragraph("一、审计结论", styles['SectionTitle']))
    risk_level = record.get('risk_level', '')
    if '严重' in risk_level:
        story.append(Paragraph(f"[!!!] 检测到严重安全风险（风险分: {record.get('risk_score', 0)}）", styles['RiskCritical']))
    elif '高' in risk_level:
        story.append(Paragraph(f"[!!] 检测到高风险（风险分: {record.get('risk_score', 0)}）", styles['RiskHigh']))
    elif '中' in risk_level:
        story.append(Paragraph(f"[!] 检测到中等风险（风险分: {record.get('risk_score', 0)}）", styles['RiskMedium']))
    else:
        story.append(Paragraph(f"[OK] 风险较低（风险分: {record.get('risk_score', 0)}）", styles['RiskLow']))
    
    story.append(Paragraph(f"策略决策: {pd.get('reason', 'N/A')}", styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))
    
    # 原始输入
    story.append(Paragraph("二、原始输入", styles['SectionTitle']))
    input_content = record.get('input_content', 'N/A')
    story.append(Paragraph(f"输入类型: {record.get('input_type', 'N/A')}", styles['CustomBody']))
    story.append(Spacer(1, 0.1*inch))
    
    # 使用代码块样式显示输入内容
    input_data = [['输入内容']]
    input_table = Table(input_data, colWidths=[6*inch])
    input_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f5f5f5')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#333333')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'ChineseFont' if FONT_REGISTERED else 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e8e8e8')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(input_table)
    story.append(Paragraph(input_content[:500], styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))
    
    # 行为链
    story.append(Paragraph("三、行为链分析", styles['SectionTitle']))
    bc = record.get('behavior_chain', {})
    if isinstance(bc, str):
        try:
            bc = json.loads(bc)
        except:
            bc = {}
    
    nodes = bc.get('nodes', [])
    if nodes:
        node_data = [['编号', '动作', '工具', '数据类型', '权限', '目标']]
        for node in nodes:
            node_data.append([
                node.get('id', 'N/A'),
                node.get('action', 'N/A'),
                node.get('tool', 'N/A'),
                node.get('data_type', 'N/A'),
                node.get('permission', 'N/A'),
                node.get('destination', 'N/A'),
            ])
        
        node_table = Table(node_data, colWidths=[0.8*inch, 1*inch, 1*inch, 1.2*inch, 1*inch, 1*inch])
        node_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1890ff')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'ChineseFont' if FONT_REGISTERED else 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d9d9d9')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#fafafa'), colors.white]),
        ]))
        story.append(node_table)
    else:
        story.append(Paragraph("暂无可展示的行为链数据", styles['CustomBody']))
    
    story.append(Spacer(1, 0.2*inch))
    
    # 命中规则
    story.append(Paragraph("四、命中安全规则", styles['SectionTitle']))
    matched_rules = record.get('matched_rules', [])
    if isinstance(matched_rules, str):
        try:
            matched_rules = json.loads(matched_rules)
        except:
            matched_rules = []
    
    if matched_rules:
        rule_data = [['规则ID', '规则名称', '类别', '分数', '等级']]
        for rule in matched_rules:
            rule_data.append([
                rule.get('id', 'N/A'),
                rule.get('name', 'N/A'),
                rule.get('category', 'N/A'),
                str(rule.get('score', 0)),
                rule.get('level', 'N/A'),
            ])
        
        rule_table = Table(rule_data, colWidths=[0.8*inch, 2.5*inch, 1.2*inch, 0.8*inch, 0.7*inch])
        rule_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1890ff')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'ChineseFont' if FONT_REGISTERED else 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d9d9d9')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#fafafa'), colors.white]),
        ]))
        story.append(rule_table)
    else:
        story.append(Paragraph("未命中安全规则", styles['CustomBody']))
    
    story.append(Spacer(1, 0.2*inch))
    
    # 风险解释与建议
    story.append(Paragraph("五、风险解释与建议", styles['SectionTitle']))
    story.append(Paragraph(f"原因: {record.get('reason', 'N/A')}", styles['CustomBody']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph(f"建议: {record.get('suggestion', 'N/A')}", styles['CustomBody']))
    
    # 最小权限建议
    advice_list = pd.get('least_privilege_advice', [])
    if advice_list:
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph("最小权限建议:", styles['CustomBody']))
        for advice in advice_list:
            story.append(Paragraph(f"• {advice}", styles['CustomBody']))
    
    story.append(Spacer(1, 0.2*inch))
    
    # 可信存证
    story.append(Paragraph("六、可信存证", styles['SectionTitle']))
    story.append(Paragraph(f"记录哈希: {record.get('record_hash', 'N/A')}", styles['CustomBody']))
    story.append(Paragraph(f"上一条哈希: {record.get('previous_hash', 'N/A')}", styles['CustomBody']))
    
    # 生成PDF
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    return pdf_bytes


def generate_scan_pdf_report(scan_task: dict, results: list, target: dict = None) -> bytes:
    """生成PDF格式的扫描报告"""
    from app.core.report_generator import aggregate_scan_results
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=18,
    )
    
    styles = _create_styles()
    story = []
    
    # 报告标题
    story.append(Paragraph("AgentFuzzer 安全扫描报告", styles['CustomTitle']))
    story.append(Paragraph(f"扫描ID: {scan_task.get('scan_id', 'N/A')}", styles['CustomSubtitle']))
    story.append(Spacer(1, 0.2*inch))
    
    # 扫描概要
    payload_results = aggregate_scan_results(results)
    total_results = scan_task.get("completed_payloads", len(payload_results))
    vulns = [r for r in payload_results if r.get("is_vulnerability")]
    vuln_count = scan_task.get("vulnerabilities_found", len(vulns))
    
    story.append(Paragraph("一、扫描概要", styles['SectionTitle']))
    
    summary_data = [
        ['靶标名称', target.get('name', scan_task.get('target_id', '')) if target else scan_task.get('target_id', '')],
        ['扫描时间', f"{scan_task.get('started_at', '')} ~ {scan_task.get('completed_at', '')}"],
        ['扫描模式', scan_task.get('scan_mode', 'N/A')],
        ['载荷总数', str(scan_task.get('total_payloads', 0))],
        ['发现漏洞', str(vuln_count)],
        ['通过率', f"{((total_results - vuln_count) / max(total_results, 1) * 100):.1f}%"],
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#333333')),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'ChineseFont' if FONT_REGISTERED else 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d9d9d9')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))
    
    # 漏洞清单
    story.append(Paragraph("二、漏洞清单", styles['SectionTitle']))
    if vulns:
        vuln_data = [['#', '载荷ID', '严重度', '描述']]
        for i, v in enumerate(vulns[:20]):
            breaches = v.get("defense_breaches", [])
            desc = breaches[0].get("description", "")[:50] if breaches else "未知"
            vuln_data.append([
                str(i+1),
                v.get('payload_id', 'N/A'),
                v.get('vulnerability_severity', 'N/A'),
                desc,
            ])
        
        vuln_table = Table(vuln_data, colWidths=[0.5*inch, 1.5*inch, 1*inch, 3*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ff4d4f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('ALIGN', (3, 1), (3, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'ChineseFont' if FONT_REGISTERED else 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d9d9d9')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#fff1f0'), colors.white]),
        ]))
        story.append(vuln_table)
    else:
        story.append(Paragraph("未发现安全漏洞 ✓", styles['CustomBody']))
    
    story.append(Spacer(1, 0.2*inch))
    
    # 生成PDF
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    return pdf_bytes
