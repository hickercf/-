"""
sandbox/agent_app/mock_data.py — 模拟数据

所有数据均为虚构，不对应任何真实个人或企业。
"""

MOCK_USERS = [
    {"user_id": "U001", "name": "张三", "phone": "138****1234", "email": "zhangsan@example.com", "vip_level": 1},
    {"user_id": "U002", "name": "李四", "phone": "139****5678", "email": "lisi@example.com", "vip_level": 3},
    {"user_id": "U003", "name": "王五", "phone": "137****9012", "email": "wangwu@example.com", "vip_level": 2},
]

MOCK_ORDERS = [
    {"order_id": "ORD-2026-001", "user_id": "U001", "product": "无线耳机", "amount": 299.0, "status": "已发货", "address": "北京市海淀区**街道**号"},
    {"order_id": "ORD-2026-002", "user_id": "U002", "product": "智能手表", "amount": 1299.0, "status": "已完成", "address": "上海市浦东新区**路**号"},
    {"order_id": "ORD-2026-003", "user_id": "U001", "product": "机械键盘", "amount": 499.0, "status": "待发货", "address": "北京市海淀区**街道**号"},
]

MOCK_LOGISTICS = [
    {"tracking_id": "LG-001", "order_id": "ORD-2026-001", "carrier": "顺丰速运", "status": "运输中", "current_location": "北京市分拣中心", "estimated_delivery": "2026-05-13"},
    {"tracking_id": "LG-002", "order_id": "ORD-2026-002", "carrier": "中通快递", "status": "已签收", "current_location": "上海市派送点", "estimated_delivery": "2026-05-10"},
]

MOCK_KB_ARTICLES = [
    {"article_id": "KB-001", "title": "退换货政策", "category": "售后服务", "content": "自签收之日起 7 天内可申请无理由退货，15 天内可申请换货。"},
    {"article_id": "KB-002", "title": "VIP 会员权益", "category": "会员服务", "content": "VIP 会员享受专属客服、优先发货、生日礼品等权益。"},
    {"article_id": "KB-003", "title": "运费说明", "category": "物流配送", "content": "订单满 99 元免运费，不满 99 元收取 6 元运费。"},
]


def get_user_by_id(user_id: str) -> dict:
    for u in MOCK_USERS:
        if u["user_id"] == user_id:
            return u.copy()
    return None


def get_orders_by_user(user_id: str) -> list:
    return [o.copy() for o in MOCK_ORDERS if o["user_id"] == user_id]


def get_order_by_id(order_id: str) -> dict:
    for o in MOCK_ORDERS:
        if o["order_id"] == order_id:
            return o.copy()
    return None


def get_logistics_by_order(order_id: str) -> dict:
    for l in MOCK_LOGISTICS:
        if l["order_id"] == order_id:
            return l.copy()
    return None


def get_kb_articles() -> list:
    return [a.copy() for a in MOCK_KB_ARTICLES]


def get_kb_article_by_id(article_id: str) -> dict:
    for a in MOCK_KB_ARTICLES:
        if a["article_id"] == article_id:
            return a.copy()
    return None
