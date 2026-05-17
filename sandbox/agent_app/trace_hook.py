"""
sandbox/agent_app/trace_hook.py — Trace 采集器

采集 Agent 执行过程中的完整事件流。
"""
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime

from .schemas import TraceEvent, AgentTrace


class TraceCollector:
    """AgentTrace 采集器"""
    
    _global_event_counter: int = 0
    
    def __init__(self, trace_id: str = None, agent_name: str = "demo_customer_agent"):
        self.trace_id = trace_id or f"TRACE-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        self.agent_name = agent_name
        self.events: List[TraceEvent] = []
        self.input_text: str = ""
        self.final_output: str = ""
        self.system_prompt_summary: Optional[str] = None
    
    def set_input(self, input_text: str):
        """设置用户输入"""
        self.input_text = input_text
        self._add_event(
            event_type="message",
            actor="user",
            evidence=f"用户输入: {input_text[:200]}",
        )
    
    def set_system_prompt(self, prompt: str):
        """设置系统提示词摘要"""
        self.system_prompt_summary = prompt[:200]
    
    def record_plan(self, plan_summary: str):
        """记录 Agent 计划"""
        self._add_event(
            event_type="plan",
            actor="agent",
            evidence=f"计划: {plan_summary[:200]}",
        )
    
    def record_tool_select(self, tool_name: str, reason: str = ""):
        """记录工具选择"""
        self._add_event(
            event_type="tool_select",
            actor="agent",
            tool=tool_name,
            evidence=f"选择工具: {tool_name}。原因: {reason[:100]}",
        )
    
    def record_tool_call(self, tool_name: str, params: Dict[str, Any], permission: str = "unknown"):
        """记录工具调用"""
        params_str = str(params)[:200]
        self._add_event(
            event_type="tool_call",
            actor="agent",
            tool=tool_name,
            action="execute",
            object=params_str,
            permission=permission,
            evidence=f"调用 {tool_name}，参数: {params_str}",
        )
    
    def record_observation(self, tool_name: str, observation: Any, data_type: str = "unknown"):
        """记录工具返回 Observation"""
        obs_str = str(observation)[:300]
        self._add_event(
            event_type="observation",
            actor="tool",
            tool=tool_name,
            data_type=data_type,
            evidence=f"{tool_name} 返回: {obs_str}",
        )
    
    def record_data_flow(self, source: str, destination: str, data_type: str, evidence: str = ""):
        """记录数据流"""
        self._add_event(
            event_type="data_flow",
            actor="system",
            data_type=data_type,
            source=source,
            destination=destination,
            evidence=evidence or f"数据从 {source} 流向 {destination}",
        )
    
    def record_output(self, output: str):
        """记录最终输出"""
        self.final_output = output
        self._add_event(
            event_type="output",
            actor="agent",
            evidence=f"最终输出: {output[:300]}",
        )
    
    def record_policy(self, action: str, reason: str = ""):
        """记录策略决策"""
        self._add_event(
            event_type="policy",
            actor="system",
            action=action,
            evidence=f"策略决策: {action}。原因: {reason[:200]}",
        )
    
    def _add_event(self, event_type: str, actor: str, **kwargs):
        """添加事件"""
        TraceCollector._global_event_counter += 1
        event = TraceEvent(
            event_id=f"evt-{TraceCollector._global_event_counter:06d}",
            event_type=event_type,
            actor=actor,
            **kwargs
        )
        self.events.append(event)
    
    def to_agent_trace(self) -> AgentTrace:
        """生成 AgentTrace"""
        return AgentTrace(
            trace_id=self.trace_id,
            source="docker_sandbox",
            agent_name=self.agent_name,
            input_text=self.input_text,
            system_prompt_summary=self.system_prompt_summary,
            events=self.events,
            final_output=self.final_output,
        )
    
    def reset(self):
        """重置采集器"""
        self.events = []
        self.input_text = ""
        self.final_output = ""
        self.system_prompt_summary = None
        self.trace_id = f"TRACE-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
