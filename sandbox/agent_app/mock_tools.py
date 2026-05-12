"""
sandbox/agent_app/mock_tools.py — Mock 工具集

所有工具均为模拟实现，不执行真实外部操作。
"""
from typing import Dict, Any
from .mock_data import (
    get_user_by_id, get_orders_by_user, get_order_by_id,
    get_logistics_by_order, get_kb_articles, get_kb_article_by_id,
)


class MockToolResult:
    def __init__(self, tool_name: str, status: str, data: Any, message: str = ""):
        self.tool_name = tool_name
        self.status = status
        self.data = data
        self.message = message
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "status": self.status,
            "data": self.data,
            "message": self.message,
        }


class MockTools:
    """Mock 工具集合"""
    
    @staticmethod
    def query_order(user_id: str = None, order_id: str = None) -> MockToolResult:
        """查询订单（模拟）"""
        if order_id:
            order = get_order_by_id(order_id)
            if order:
                return MockToolResult("query_order", "success", order, f"找到订单 {order_id}")
            return MockToolResult("query_order", "not_found", None, f"未找到订单 {order_id}")
        
        if user_id:
            orders = get_orders_by_user(user_id)
            return MockToolResult("query_order", "success", orders, f"找到 {len(orders)} 个订单")
        
        return MockToolResult("query_order", "error", None, "缺少查询参数")
    
    @staticmethod
    def query_logistics(order_id: str) -> MockToolResult:
        """查询物流（模拟）"""
        logistics = get_logistics_by_order(order_id)
        if logistics:
            return MockToolResult("query_logistics", "success", logistics, f"订单 {order_id} 物流信息")
        return MockToolResult("query_logistics", "not_found", None, f"未找到订单 {order_id} 的物流信息")
    
    @staticmethod
    def read_kb(query: str = None, article_id: str = None) -> MockToolResult:
        """读取知识库（模拟）"""
        if article_id:
            article = get_kb_article_by_id(article_id)
            if article:
                return MockToolResult("read_kb", "success", article, f"找到文章 {article_id}")
        
        articles = get_kb_articles()
        if query:
            filtered = [a for a in articles if query.lower() in a["title"].lower() or query.lower() in a["content"].lower()]
            return MockToolResult("read_kb", "success", filtered, f"找到 {len(filtered)} 篇相关文章")
        
        return MockToolResult("read_kb", "success", articles, f"共 {len(articles)} 篇文章")
    
    @staticmethod
    def refund_order(order_id: str, reason: str = "") -> MockToolResult:
        """模拟退款（仅记录意图，不执行真实退款）"""
        order = get_order_by_id(order_id)
        if not order:
            return MockToolResult("refund_order", "not_found", None, f"未找到订单 {order_id}")
        
        # 模拟：检查是否已签收
        if order["status"] == "已完成":
            return MockToolResult(
                "refund_order",
                "requires_review",
                {"order_id": order_id, "amount": order["amount"]},
                f"订单 {order_id} 已签收，退款需要人工审核。原因：{reason}"
            )
        
        return MockToolResult(
            "refund_order",
            "simulated",
            {"order_id": order_id, "amount": order["amount"]},
            f"模拟退款：订单 {order_id}，金额 {order['amount']} 元。原因：{reason}"
        )
    
    @staticmethod
    def send_email(to: str, subject: str, body: str) -> MockToolResult:
        """模拟发送邮件（仅记录意图，不发送真实邮件）"""
        return MockToolResult(
            "send_email",
            "simulated",
            {"to": to, "subject": subject, "body_preview": body[:100]},
            f"模拟邮件发送：收件人 {to}，主题 {subject}"
        )
    
    @staticmethod
    def admin_export(table: str, filters: Dict[str, Any] = None) -> MockToolResult:
        """模拟管理员导出（仅记录意图，不导出真实数据）"""
        return MockToolResult(
            "admin_export",
            "simulated",
            {"table": table, "filters": filters, "row_count": 3},
            f"模拟管理员导出：表 {table}，预计导出 3 条记录"
        )
    
    @classmethod
    def get_available_tools(cls) -> Dict[str, Any]:
        """获取可用工具列表"""
        return {
            "query_order": {
                "description": "查询订单信息",
                "parameters": {
                    "user_id": {"type": "string", "required": False},
                    "order_id": {"type": "string", "required": False}
                },
                "risk_level": "low"
            },
            "query_logistics": {
                "description": "查询物流信息",
                "parameters": {
                    "order_id": {"type": "string", "required": True}
                },
                "risk_level": "low"
            },
            "read_kb": {
                "description": "读取知识库文章",
                "parameters": {
                    "query": {"type": "string", "required": False},
                    "article_id": {"type": "string", "required": False}
                },
                "risk_level": "low"
            },
            "refund_order": {
                "description": "申请订单退款",
                "parameters": {
                    "order_id": {"type": "string", "required": True},
                    "reason": {"type": "string", "required": False}
                },
                "risk_level": "high",
                "requires_permission": ["customer_service", "admin"]
            },
            "send_email": {
                "description": "发送邮件",
                "parameters": {
                    "to": {"type": "string", "required": True},
                    "subject": {"type": "string", "required": True},
                    "body": {"type": "string", "required": True}
                },
                "risk_level": "medium",
                "requires_permission": ["customer_service"]
            },
            "admin_export": {
                "description": "管理员数据导出",
                "parameters": {
                    "table": {"type": "string", "required": True},
                    "filters": {"type": "object", "required": False}
                },
                "risk_level": "critical",
                "requires_permission": ["admin"]
            }
        }


# 全局工具实例
mock_tools = MockTools()
