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
    "Qwen/Qwen2.5-7B-Instruct",
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
        return json.loads(resp.read().decode("utf-8")), resp.status, round(time.perf_counter() - started, 4)


def direct_probe(model, api_key):
    body = {
        "model": model,
        "messages": [{"role": "user", "content": "Say OK only."}],
        "max_tokens": 8,
        "temperature": 0,
    }
    try:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            BASE_URL + "/chat/completions",
            data=data,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": "Bearer " + api_key,
            },
            method="POST",
        )
        started = time.perf_counter()
        with urllib.request.urlopen(req, timeout=120) as raw:
            resp = json.loads(raw.read().decode("utf-8"))
            status = raw.status
            elapsed = round(time.perf_counter() - started, 4)
        return {
            "ok": True,
            "status": status,
            "elapsed_sec": elapsed,
            "output": resp.get("choices", [{}])[0].get("message", {}).get("content", "")[:200],
        }
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": exc.code, "error": exc.read().decode("utf-8", errors="replace")[:1000]}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


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


def docker_recreate(model, api_key):
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
            timeout=2400,
        )
        return {"ok": True, "http_status": status, "elapsed_sec": elapsed, "response": response}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "http_status": exc.code, "error": exc.read().decode("utf-8", errors="replace")}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def summarize(response):
    results = response.get("results", []) if isinstance(response, dict) else []
    return {
        "total": response.get("total"),
        "attack_success_count": response.get("attack_success_count"),
        "defense_success_count": response.get("defense_success_count"),
        "error_count": response.get("error_count"),
        "attack_success_rate": response.get("attack_success_rate"),
        "total_time_s": response.get("total_time_s"),
        "avg_time_ms": response.get("avg_time_ms"),
        "severity_counts": dict(Counter(r.get("severity", "unknown") for r in results)),
        "attack_type_counts": dict(Counter(r.get("attack_type", "") for r in results if r.get("attack_type"))),
    }


def main():
    api_key = os.environ.get("SF_KEY", "")
    if not api_key:
        raise SystemExit("SF_KEY is required")

    runs = []
    for model in MODELS:
        print(f"=== MODEL {model} ===", flush=True)
        direct = direct_probe(model, api_key)
        print(json.dumps({"direct_probe": redact(direct)}, ensure_ascii=False), flush=True)
        run = {
            "model": model,
            "base_url": BASE_URL,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "direct_probe": redact(direct),
        }
        if not direct.get("ok"):
            run["poison"] = {"ok": False, "error": "direct_probe_failed"}
        else:
            try:
                docker_recreate(model, api_key)
                smoke = smoke_test()
                run["smoke"] = redact(smoke)
                print(json.dumps({"smoke": run["smoke"]}, ensure_ascii=False), flush=True)
                if smoke.get("is_fallback"):
                    run["poison"] = {"ok": False, "error": "smoke_test_fallback"}
                else:
                    poison = run_poison_all()
                    run["poison"] = redact(poison)
                    if poison.get("ok"):
                        run["summary"] = summarize(poison["response"])
            except Exception as exc:
                run["poison"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        run["finished_at"] = datetime.now().isoformat(timespec="seconds")
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", model)
        detail_path = RESULT_DIR / f"remaining_dynamic_poison_{safe_name}_{TS}.json"
        detail_path.write_text(json.dumps(run, ensure_ascii=False, indent=2), encoding="utf-8")
        run["detail_file"] = detail_path.name
        runs.append(run)
        print(json.dumps({"summary": run.get("summary"), "detail_file": run["detail_file"], "error": run.get("poison", {}).get("error")}, ensure_ascii=False), flush=True)

    report = RESULT_DIR / f"remaining_siliconflow_dynamic_report_{TS}.md"
    lines = [
        "# 硅基流动剩余低级模型动态投毒补测报告",
        "",
        f"- 测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "- Base URL: `https://api.siliconflow.cn/v1`",
        "- 数据集: all = 180 条",
        "- 并发: 3",
        "- API key: 已脱敏，未写入报告",
        "",
        "| Model | Direct Probe | Smoke fallback | 总数 | 攻击成功 | 防御成功 | 错误 | 成功率 | 明细 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for run in runs:
        summary = run.get("summary", {})
        lines.append(
            f"| {run['model']} | {run.get('direct_probe', {}).get('ok')} | {run.get('smoke', {}).get('is_fallback', '')} | "
            f"{summary.get('total', '')} | {summary.get('attack_success_count', '')} | {summary.get('defense_success_count', '')} | "
            f"{summary.get('error_count', '')} | {summary.get('attack_success_rate', '')} | `{run['detail_file']}` |"
        )
    lines += ["", "## 观察", ""]
    for run in runs:
        if run.get("summary"):
            s = run["summary"]
            lines.append(f"- {run['model']}: {s['attack_success_count']}/{s['total']} 攻击成功，成功率 {s['attack_success_rate']}。")
        else:
            lines.append(f"- {run['model']}: 未完成，原因 {run.get('poison', {}).get('error')}")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    aggregate = RESULT_DIR / f"remaining_siliconflow_dynamic_all_{TS}.json"
    aggregate.write_text(json.dumps({"runs": runs, "report": report.name}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"report_path": str(report), "aggregate_path": str(aggregate)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
