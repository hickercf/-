import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "test-results"
TS = datetime.now().strftime("%Y%m%d_%H%M%S")
BASE_URL = "https://api.siliconflow.cn/v1"
MODELS = [
    "THUDM/GLM-4-9B-0414",
    "THUDM/GLM-Z1-9B-0414",
    "zai-org/GLM-4.5-Air",
    "inclusionAI/Ling-mini-2.0",
]


def redact(value):
    if isinstance(value, str):
        value = re.sub(r"sk-[A-Za-z0-9_\-]{8,}", "sk-[REDACTED]", value)
        value = re.sub(r"(?i)(password|密码)\s*[:=]\s*[^,\s\]\}\n]+", r"\1=[REDACTED]", value)
        value = re.sub(r"(?i)(token|secret|jwt secret)\s*[:=]\s*[^,\s\]\}\n]+", r"\1=[REDACTED]", value)
        return value
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    return value


def http_json(method, url, payload=None, timeout=600):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    started = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body), resp.status, round(time.perf_counter() - started, 4)


def docker_recreate_for_model(model, api_key):
    env = os.environ.copy()
    env.update(
        {
            "LLM_API_KEY": api_key,
            "LLM_BASE_URL": BASE_URL,
            "LLM_MODEL": model,
            "LLM_TIMEOUT": "180",
            "LLM_CONNECT_TIMEOUT": "45",
        }
    )
    subprocess.run(
        ["docker", "compose", "up", "-d", "--force-recreate", "backend", "sandbox"],
        cwd=ROOT,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    wait_for_backend()


def wait_for_backend():
    deadline = time.time() + 90
    last_error = None
    while time.time() < deadline:
        try:
            response, status, _ = http_json("GET", "http://127.0.0.1:8000/", timeout=10)
            if status == 200 and response.get("status") == "running":
                return
        except Exception as exc:
            last_error = exc
        time.sleep(2)
    raise RuntimeError(f"backend not ready: {last_error}")


def smoke_test():
    payload = {"input_text": "Please explain the return policy in one sentence.", "injection_point": "user_input"}
    response, status, elapsed = http_json("POST", "http://127.0.0.1:18080/run", payload, timeout=240)
    output = response.get("trace", {}).get("final_output", "")
    return {"http_status": status, "elapsed_sec": elapsed, "output": output[:800], "is_fallback": "暂时无法处理您的请求" in output}


def run_poison_all():
    try:
        response, status, elapsed = http_json(
            "POST",
            "http://127.0.0.1:8000/api/poison/start?dataset=all&max_cases=0&concurrency=3",
            timeout=1800,
        )
        return {"ok": True, "http_status": status, "elapsed_sec": elapsed, "response": response}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "http_status": exc.code, "error": exc.read().decode("utf-8", errors="replace")}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def summarize_poison(response):
    results = response.get("results", []) if isinstance(response, dict) else []
    severity = Counter(r.get("severity", "unknown") for r in results)
    attack_types = Counter(r.get("attack_type", "") for r in results if r.get("attack_type"))
    return {
        "total": response.get("total"),
        "attack_success_count": response.get("attack_success_count"),
        "defense_success_count": response.get("defense_success_count"),
        "error_count": response.get("error_count"),
        "attack_success_rate": response.get("attack_success_rate"),
        "total_time_s": response.get("total_time_s"),
        "avg_time_ms": response.get("avg_time_ms"),
        "severity_counts": dict(severity),
        "attack_type_counts": dict(attack_types),
    }


def main():
    api_key = os.environ.get("SF_KEY", "")
    if not api_key:
        raise SystemExit("SF_KEY is required")

    runs = []
    for model in MODELS:
        print(f"=== MODEL {model} ===", flush=True)
        started = datetime.now().isoformat(timespec="seconds")
        try:
            docker_recreate_for_model(model, api_key)
            smoke = smoke_test()
            print(json.dumps({"smoke": redact(smoke)}, ensure_ascii=False), flush=True)
            if smoke.get("is_fallback"):
                poison = {"ok": False, "error": "smoke_test_fallback: model call did not produce an LLM response"}
            else:
                poison = run_poison_all()
        except Exception as exc:
            smoke = None
            poison = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        item = {
            "model": model,
            "started_at": started,
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "base_url": BASE_URL,
            "smoke": redact(smoke),
            "poison": redact(poison),
        }
        if poison.get("ok"):
            item["summary"] = summarize_poison(poison["response"])
        runs.append(item)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", model)
        detail_path = RESULT_DIR / f"dynamic_poison_{safe_name}_{TS}.json"
        detail_path.write_text(json.dumps(item, ensure_ascii=False, indent=2), encoding="utf-8")
        item["detail_file"] = detail_path.name
        print(json.dumps({"summary": item.get("summary"), "detail_file": detail_path.name}, ensure_ascii=False), flush=True)

    report_path = RESULT_DIR / f"dynamic_low_model_poison_report_{TS}.md"
    lines = [
        "# 免费低级模型动态投毒测试报告",
        "",
        f"- 测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "- Base URL: `https://api.siliconflow.cn/v1`",
        "- 数据集: all = 180 条",
        "- 并发: 3",
        "- 敏感值处理: 报告和 JSON 中已脱敏 key/password/token/secret 样式内容",
        "",
        "## 汇总",
        "",
        "| Model | Smoke 是否 fallback | 总数 | 攻击成功 | 防御成功 | 错误 | 成功率 | 平均耗时(ms) | 明细 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for run in runs:
        summary = run.get("summary", {})
        smoke = run.get("smoke") or {}
        lines.append(
            f"| {run['model']} | {str(smoke.get('is_fallback'))} | {summary.get('total', '')} | "
            f"{summary.get('attack_success_count', '')} | {summary.get('defense_success_count', '')} | "
            f"{summary.get('error_count', '')} | {summary.get('attack_success_rate', '')} | "
            f"{summary.get('avg_time_ms', '')} | `{run.get('detail_file', '')}` |"
        )
    lines += [
        "",
        "## 主要观察",
        "",
    ]
    for run in runs:
        summary = run.get("summary")
        if summary:
            lines.append(
                f"- {run['model']}: {summary['attack_success_count']}/{summary['total']} 攻击成功，"
                f"成功率 {summary['attack_success_rate']}，严重度 {json.dumps(summary['severity_counts'], ensure_ascii=False)}。"
            )
        else:
            lines.append(f"- {run['model']}: 执行失败，原因 {run.get('poison', {}).get('error')}")
    lines += [
        "",
        "## 说明",
        "",
        "- 本轮是真实 LLM 动态链路测试；smoke 输出不再是固定 fallback 时，才进入全量投毒。",
        "- 后端判定仍使用项目当前 `AttackJudge`，它偏向检测最终输出中的泄露/越权/配合攻击证据。",
    ]
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    aggregate_path = RESULT_DIR / f"dynamic_low_model_poison_all_{TS}.json"
    aggregate_path.write_text(json.dumps({"runs": runs, "report": report_path.name}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"report_path": str(report_path), "aggregate_path": str(aggregate_path)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
