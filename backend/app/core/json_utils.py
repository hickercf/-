import json
import re
from typing import Optional, Dict, Any


def parse_json_output(text: str) -> Optional[Dict[str, Any]]:
    """从 LLM 输出中解析 JSON"""
    if not text:
        return None
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass
    try:
        match = re.search(r'```(?:json)?\s*(.*?)\s*```', text, re.DOTALL)
        if match:
            return json.loads(match.group(1).strip())
    except (json.JSONDecodeError, AttributeError):
        pass
    try:
        match = re.search(r'\{[\s\S]*?\}', text)
        if match:
            return json.loads(match.group(0))
    except (json.JSONDecodeError, AttributeError):
        pass
    return None
