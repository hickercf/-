"""
trace_adapter.py — AgentTrace 统一适配器

将 AgentTrace 转换为 BehaviorChain，供规则引擎和风险引擎使用。
支持多种来源：Docker 靶场、LangChain 日志、手动输入等。
"""
from typing import List, Dict, Any, Optional
import uuid

from app.schemas.trace_schema import AgentTrace, TraceEvent
from app.schemas.behavior_schema import BehaviorNode, BehaviorEdge, BehaviorChain


# ── 事件类型 → 行为节点映射 ──────────────────────────────────────

EVENT_TYPE_TO_ACTION = {
    "tool_call": "execute",
    "data_flow": "send",
    "output": "leak",
    "plan": "read",
    "tool_select": "query",
    "observation": "read",
    "message": "read",
    "policy": "override",
}

EVENT_TOOL_MAP = {
    "query_order": "database",
    "query_logistics": "database",
    "read_kb": "llm",
    "refund_order": "database",
    "send_email": "email",
    "admin_export": "database",
    "shell": "shell",
    "file_read": "file",
    "file_write": "file",
    "browser": "browser",
    "network": "network",
    "code": "code",
}

DATA_TYPE_MAP = {
    "order_info": "database_record",
    "personal_info": "personal_info",
    "credential": "credential",
    "password": "password",
    "token": "token",
    "api_key": "api_key",
    "system_file": "system_file",
    "prompt": "prompt",
    "email_content": "personal_info",
    "kb_content": "public_data",
    "logistics_info": "public_data",
}


def _infer_tool(event: TraceEvent) -> str:
    """从事件中推断工具类型"""
    if event.tool:
        return EVENT_TOOL_MAP.get(event.tool, event.tool)
    # 从 action/object 推断
    if event.action in ("send", "upload"):
        return "email"
    if event.action in ("read", "write", "delete"):
        return "file"
    if event.action in ("execute", "run"):
        return "shell"
    if event.action in ("query", "modify"):
        return "database"
    return "unknown"


def _infer_action(event: TraceEvent) -> str:
    """从事件中推断动作类型"""
    if event.action:
        return event.action
    return EVENT_TYPE_TO_ACTION.get(event.event_type, "unknown")


def _infer_data_type(event: TraceEvent) -> str:
    """从事件中推断数据类型"""
    if event.data_type:
        return DATA_TYPE_MAP.get(event.data_type, event.data_type)
    # 从 object 推断
    obj = (event.object or "").lower()
    if any(k in obj for k in ["password", "密码"]):
        return "password"
    if any(k in obj for k in ["token", "密钥", "api_key", "secret"]):
        return "token"
    if any(k in obj for k in ["credential", "凭证"]):
        return "credential"
    if any(k in obj for k in ["personal", "personal_info", "个人信息", "手机号", "身份证"]):
        return "personal_info"
    if any(k in obj for k in ["order", "订单"]):
        return "database_record"
    if any(k in obj for k in ["system", "系统文件", "config"]):
        return "system_file"
    return "unknown"


def _infer_destination(event: TraceEvent) -> str:
    """推断数据目的地"""
    if event.destination:
        return event.destination
    if event.event_type == "data_flow":
        return "external"
    if event.event_type == "output" and event.data_type in ("personal_info", "password", "token", "credential"):
        return "external"
    return "local"


def _infer_permission(event: TraceEvent, agent_constraints: List[str] = None) -> str:
    """推断权限状态"""
    if event.permission:
        return event.permission
    # 检查是否越权
    tool = _infer_tool(event)
    action = _infer_action(event)
    constraints = agent_constraints or []
    
    # 管理员操作
    if tool == "database" and action in ("delete", "override"):
        if any("admin" in c.lower() or "管理" in c for c in constraints):
            return "authorized"
        return "unauthorized"
    
    # 敏感数据外发
    if action in ("send", "upload", "leak"):
        return "unauthorized"
    
    # 默认
    if event.actor == "agent":
        return "authorized"
    return "unknown"


def trace_event_to_node(
    event: TraceEvent,
    index: int,
    agent_constraints: List[str] = None
) -> BehaviorNode:
    """将单个 TraceEvent 转换为 BehaviorNode"""
    return BehaviorNode(
        id=f"node-{index}",
        actor=event.actor,
        tool=_infer_tool(event),
        action=_infer_action(event),
        object=event.object or event.evidence[:100] or "unknown",
        data_type=_infer_data_type(event),
        permission=_infer_permission(event, agent_constraints),
        destination=_infer_destination(event),
        confidence=0.85,
        evidence_text=event.evidence,
    )


def trace_events_to_nodes(
    events: List[TraceEvent],
    agent_constraints: List[str] = None
) -> List[BehaviorNode]:
    """批量转换 TraceEvent 列表为 BehaviorNode 列表"""
    return [
        trace_event_to_node(evt, i, agent_constraints)
        for i, evt in enumerate(events)
    ]


def build_edges_from_events(events: List[TraceEvent]) -> List[BehaviorEdge]:
    """从事件序列构建行为边"""
    edges = []
    for i in range(len(events) - 1):
        evt1, evt2 = events[i], events[i + 1]
        
        # 判断关系类型
        relation = "then"
        description = f"{evt1.event_type} → {evt2.event_type}"
        
        # 数据流关系
        if evt1.event_type == "tool_call" and evt2.event_type == "observation":
            relation = "data_flow"
            description = f"工具 {evt1.tool} 返回 Observation"
        elif evt1.event_type == "observation" and evt2.event_type == "tool_select":
            relation = "control_flow"
            description = "Observation 影响后续工具选择"
        elif evt1.event_type == "tool_call" and evt2.event_type == "data_flow":
            relation = "data_flow"
            description = f"数据从 {evt1.tool} 流向 {evt2.destination or 'unknown'}"
        elif evt1.event_type == "data_flow" and evt2.event_type == "output":
            relation = "data_flow"
            description = "敏感数据通过输出泄露"
        
        edges.append(BehaviorEdge(
            source=f"node-{i}",
            target=f"node-{i+1}",
            relation=relation,
            description=description,
        ))
    
    # 检测跨信任边界的数据流
    for i, evt in enumerate(events):
        if evt.event_type == "data_flow":
            dst = evt.destination or "local"
            if dst == "external":
                edges.append(BehaviorEdge(
                    source=f"node-{i}",
                    target="external",
                    relation="data_flow",
                    description="数据跨越信任边界外发",
                ))
    
    return edges


def agent_trace_to_behavior_chain(
    trace: AgentTrace,
    agent_constraints: List[str] = None
) -> BehaviorChain:
    """将 AgentTrace 转换为 BehaviorChain
    
    这是核心转换函数，将 Docker 靶场或任何来源的 AgentTrace
    统一转换为审计引擎可处理的行为链。
    """
    nodes = trace_events_to_nodes(trace.events, agent_constraints)
    edges = build_edges_from_events(trace.events)
    
    # 检测是否跨越信任边界
    trust_boundary_crossed = any(
        edge.relation == "data_flow" and edge.target == "external"
        for edge in edges
    )
    
    return BehaviorChain(
        trace_id=trace.trace_id,
        input_type="task",
        nodes=nodes,
        edges=edges,
        trust_boundary_crossed=trust_boundary_crossed,
        extraction_method="hybrid",
        extraction_confidence=0.9,
    )


def dict_to_agent_trace(trace_dict: Dict[str, Any]) -> AgentTrace:
    """将字典转换为 AgentTrace 对象"""
    events = trace_dict.get("events", [])
    trace_dict["events"] = [
        TraceEvent(**evt) if isinstance(evt, dict) else evt
        for evt in events
    ]
    return AgentTrace(**trace_dict)


def manual_trace_to_agent_trace(
    input_text: str,
    behavior_chain: Dict[str, Any],
    trace_id: str = None
) -> AgentTrace:
    """将手动输入/行为链转换为 AgentTrace"""
    trace_id = trace_id or f"TRACE-{uuid.uuid4().hex[:12].upper()}"
    
    events = []
    nodes = behavior_chain.get("nodes", [])
    for i, node in enumerate(nodes):
        events.append(TraceEvent(
            event_id=f"evt-{i}",
            event_type="tool_call" if node.get("tool") != "unknown" else "message",
            actor=node.get("actor", "agent"),
            tool=node.get("tool"),
            action=node.get("action"),
            object=node.get("object"),
            data_type=node.get("data_type"),
            permission=node.get("permission"),
            destination=node.get("destination"),
            evidence=node.get("evidence_text", ""),
        ))
    
    return AgentTrace(
        trace_id=trace_id,
        source="manual",
        agent_name="manual_input",
        input_text=input_text,
        events=events,
        final_output=behavior_chain.get("final_output", ""),
    )
