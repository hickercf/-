import os
import asyncio
import httpx
from dotenv import load_dotenv

load_dotenv()


LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "60"))
LLM_CONNECT_TIMEOUT = float(os.getenv("LLM_CONNECT_TIMEOUT", "30"))


def build_chat_llm(*, model: str, api_key: str, base_url: str, temperature: float, max_tokens: int):
    """Build ChatOpenAI with explicit async HTTP settings for stable Windows networking."""
    from langchain_openai import ChatOpenAI

    timeout = httpx.Timeout(LLM_TIMEOUT, connect=LLM_CONNECT_TIMEOUT)
    return ChatOpenAI(
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
        max_tokens=max_tokens,
        request_timeout=timeout,
        http_client=httpx.Client(timeout=timeout),
        http_async_client=httpx.AsyncClient(timeout=timeout),
        http_socket_options=(),
    )


def safe_log(message: str) -> None:
    try:
        print(message)
    except UnicodeEncodeError:
        print(message.encode("ascii", "backslashreplace").decode("ascii"))


def _sync_chat_completion(*, model: str, api_key: str, base_url: str, messages: list, temperature: float, max_tokens: int) -> str:
    response = httpx.post(
        base_url.rstrip("/") + "/chat/completions",
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        },
        timeout=httpx.Timeout(LLM_TIMEOUT, connect=LLM_CONNECT_TIMEOUT),
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]


async def chat_completion_text(*, model: str, api_key: str, base_url: str, messages: list, temperature: float, max_tokens: int) -> str:
    return await asyncio.to_thread(
        _sync_chat_completion,
        model=model,
        api_key=api_key,
        base_url=base_url,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )