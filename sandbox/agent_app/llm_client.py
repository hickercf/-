"""
sandbox/agent_app/llm_client.py — 沙箱 Agent 的 LLM 客户端

使用 httpx 直接调用 DeepSeek API。
"""
import os
import httpx
from dotenv import load_dotenv

load_dotenv()

LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "90"))
LLM_CONNECT_TIMEOUT = float(os.getenv("LLM_CONNECT_TIMEOUT", "45"))


def call_llm(system_prompt: str, user_message: str, temperature: float = 0.7, max_tokens: int = 512) -> str:
    """同步调用 LLM，返回回复文本。失败返回空字符串。"""
    if not LLM_API_KEY:
        return ""
    try:
        resp = httpx.post(
            LLM_BASE_URL.rstrip("/") + "/chat/completions",
            headers={
                "Authorization": f"Bearer {LLM_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": LLM_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
            timeout=httpx.Timeout(LLM_TIMEOUT, connect=LLM_CONNECT_TIMEOUT),
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[LLM Error] {e}")
        return ""
