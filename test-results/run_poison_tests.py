import asyncio
import json
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, request

ROOT = Path(__file__).resolve().parents[1]
DATASETS = [
    ("test_cases", ROOT / "dataset" / "test_cases.json"),
    ("prompt_attacks_100", ROOT / "dataset" / "prompt_attacks_100.json"),
    ("adversarial_cases", ROOT / "dataset" / "adversarial_cases.json"),
]
AGENTS = [
    ("high_security_agent", "http://127.0.0.1:50001/callback"),
    ("medium_security_agent", "http://127.0.0.1:50002/callback"),
    ("low_security_agent", "http://127.0.0.1:50003/callback"),
    ("vulnerable_agent", "http://127.0.0.1:50004/callback"),
]
RESULT_DIR = ROOT / "test-results"
TS = datetime.now().strftime("%Y%m%d_%H%M%S")


def redact(value):
    if isinstance(value, str):
        value = re.sub(r"sk-[A-Za-z0-9_\-]{8,}", "sk-[REDACTED]", value)
        value = re.sub(r"AKIA[A-Z0-9]{16}", "AKIA[REDACTED]", value)
        value = re.sub(r"(?i)(password|密码)\s*[:=]\s*[^,\s\]\}\n]+", r"\1=[REDACTED]", value)
        value = re.sub(r"(?i)(token|secret|jwt secret)\s*[:=]\s*[^,\s\]\}\n]+", r"\1=[REDACTED]", value)
        return value
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    return value


def http_json(method, url, payload=None, timeout=30):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=data, headers=headers, method=method)
    started = time.perf_counter()
    with request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        elapsed = time.perf_counter() - started
        return json.loads(body), resp.status, elapsed


def load_cases():
    cases = []
    for dataset, path in DATASETS:
        data = json.loads(path.read_text(encoding="utf-8"))
        for idx, case in enumerate(data, start=1):
            content = case.get("content") or case.get("prompt") or case.get("input") or ""
            cases.append(
                {
                    "dataset": dataset,
                    "case_index": idx,
                    "id": case.get("id") or f"{dataset}-{idx:03d}",
                    "content": content,
                    "expected_level": case.get("expected_level") or case.get("expected") or "",
                    "expected_categories": case.get("expected_categories") or [case.get("category", "")],
                    "expected_policy": case.get("expected_policy") or "",
                    "raw": case,
                }
            )
    return cases


def judge_trace(input_text, trace):
    import sys

    app_path = str(ROOT / "backend" / "app")
    if app_path not in sys.path:
        sys.path.insert(0, app_path)
    from core.attack_judge import attack_judge

    return attack_judge.judge(input_text, trace)


def summarize_results(results):
    by_agent = defaultdict(list)
    for item in results:
        by_agent[item["agent"]].append(item)
    summary = {
        "total_requests": len(results),
        "agents": {},
    }
    for agent, rows in by_agent.items():
        total = len(rows)
        errors = sum(1 for r in rows if r.get("error"))
        successes = sum(1 for r in rows if r.get("judgement", {}).get("attack_success"))
        levels = Counter((r.get("judgement") or {}).get("severity", "error" if r.get("error") else "unknown") for r in rows)
        attack_types = Counter((r.get("judgement") or {}).get("attack_type", "") for r in rows if (r.get("judgement") or {}).get("attack_type"))
        datasets = Counter(r["dataset"] for r in rows)
        summary["agents"][agent] = {
            "total": total,
            "errors": errors,
            "attack_success_count": successes,
            "defense_success_count": total - errors - successes,
            "attack_success_rate": round(successes / total, 4) if total else 0,
            "severity_counts": dict(levels),
            "attack_type_counts": dict(attack_types),
            "dataset_counts": dict(datasets),
        }
    return summary


async def run_direct_agent_tests(cases):
    results = []
    for agent_name, url in AGENTS:
        for case in cases:
            entry = {
                "agent": agent_name,
                "url": url,
                "dataset": case["dataset"],
                "case_id": case["id"],
                "input_text": case["content"],
                "expected_level": case["expected_level"],
                "expected_categories": case["expected_categories"],
            }
            try:
                trace, status, elapsed = http_json(
                    "POST",
                    url,
                    {"message": case["content"], "user_id": "poison-test"},
                    timeout=20,
                )
                judgement = judge_trace(case["content"], trace)
                entry.update(
                    {
                        "http_status": status,
                        "elapsed_sec": round(elapsed, 4),
                        "trace": trace,
                        "judgement": judgement,
                    }
                )
            except Exception as exc:
                entry.update({"error": f"{type(exc).__name__}: {exc}"})
            results.append(redact(entry))
    return {"summary": summarize_results(results), "results": results}


def run_sandbox_poison():
    payload = None
    try:
        payload, status, elapsed = http_json(
            "POST",
            "http://127.0.0.1:8000/api/poison/start?dataset=all&max_cases=0&concurrency=6",
            timeout=300,
        )
        return {
            "ok": True,
            "http_status": status,
            "elapsed_sec": round(elapsed, 4),
            "response": redact(payload),
        }
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"ok": False, "http_status": exc.code, "error": redact(body)}
    except Exception as exc:
        return {"ok": False, "error": redact(f"{type(exc).__name__}: {exc}")}


async def main():
    cases = load_cases()
    preflight = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "case_total": len(cases),
        "dataset_counts": dict(Counter(c["dataset"] for c in cases)),
        "agents": [name for name, _ in AGENTS],
    }
    direct = await run_direct_agent_tests(cases)
    sandbox = run_sandbox_poison()

    direct_path = RESULT_DIR / f"fallback_agent_poison_results_{TS}.json"
    sandbox_path = RESULT_DIR / f"sandbox_poison_all_180_results_{TS}.json"
    report_path = RESULT_DIR / f"poison_full_test_report_{TS}.md"

    direct_path.write_text(json.dumps({"preflight": preflight, **direct}, ensure_ascii=False, indent=2), encoding="utf-8")
    sandbox_path.write_text(json.dumps({"preflight": preflight, **sandbox}, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# Agent 自动化投毒与沙箱测试报告",
        "",
        f"- 测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "- 执行模式: fallback 直接回调测试 + Docker sandbox 自动化投毒",
        "- 数据集: test_cases.json 30 条、prompt_attacks_100.json 100 条、adversarial_cases.json 50 条",
        f"- 总攻击样本: {len(cases)}",
        "- 敏感值处理: 报告和 JSON 结果中已对 sk/API key/password/token/secret 样式内容脱敏",
        "",
        "## 运行环境",
        "",
        "- Backend: http://127.0.0.1:8000",
        "- Sandbox: http://127.0.0.1:18080",
        "- Test agents: high 50001, medium 50002, low 50003, vulnerable 50004",
        "",
        "## Fallback 直接回调测试汇总",
        "",
        "| Agent | 请求数 | 攻击成功 | 防御成功 | 错误 | 攻击成功率 | 严重度分布 |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for agent, item in direct["summary"]["agents"].items():
        lines.append(
            f"| {agent} | {item['total']} | {item['attack_success_count']} | "
            f"{item['defense_success_count']} | {item['errors']} | {item['attack_success_rate']:.2%} | "
            f"{json.dumps(item['severity_counts'], ensure_ascii=False)} |"
        )

    sandbox_response = sandbox.get("response", {}) if sandbox.get("ok") else {}
    lines += [
        "",
        "## Docker Sandbox 自动化投毒汇总",
        "",
    ]
    if sandbox.get("ok"):
        lines += [
            f"- HTTP 状态: {sandbox['http_status']}",
            f"- 耗时: {sandbox['elapsed_sec']} 秒",
            f"- 总样本: {sandbox_response.get('total')}",
            f"- 攻击成功: {sandbox_response.get('attack_success_count')}",
            f"- 防御成功: {sandbox_response.get('defense_success_count')}",
            f"- 错误数: {sandbox_response.get('error_count')}",
            f"- 攻击成功率: {sandbox_response.get('attack_success_rate')}",
        ]
    else:
        lines += [
            f"- 执行失败: {sandbox.get('error')}",
            f"- HTTP 状态: {sandbox.get('http_status', 'n/a')}",
        ]

    lines += [
        "",
        "## 主要发现",
        "",
    ]
    for agent, item in direct["summary"]["agents"].items():
        lines.append(
            f"- {agent}: {item['attack_success_count']}/{item['total']} 成功，"
            f"成功率 {item['attack_success_rate']:.2%}，主要类型 {json.dumps(item['attack_type_counts'], ensure_ascii=False)}。"
        )
    if sandbox.get("ok"):
        lines.append(
            f"- sandbox demo_customer_agent: {sandbox_response.get('attack_success_count')}/"
            f"{sandbox_response.get('total')} 成功，成功率 {sandbox_response.get('attack_success_rate')}。"
        )

    lines += [
        "",
        "## 详细日志索引",
        "",
        f"- Fallback agent 全量 JSON: `{direct_path.name}`",
        f"- Sandbox 投毒全量 JSON: `{sandbox_path.name}`",
        "",
        "## Bug / 风险记录",
        "",
        "- Backend `/health` 返回 404，健康检查可用性依赖 compose healthcheck 或其他路由；人工烟测时不直观。",
        "- `/api/poison/start` 当前只针对内置 sandbox agent，不能按 target_id 分别跑四个外部 callback agent；外部 agent 测试需要脚本直连 `/callback`。",
        "- sandbox agent 在无 LLM key 时会静默降级到规则 fallback，仅覆盖订单关键词逻辑；这符合本次 fallback 测试，但不等价于真实 DeepSeek 推理链路。",
        "- `AttackJudge` 对“请求被警告，但可能继续处理”这类中等安全 agent 输出判定偏保守，可能低估部分仅告警未阻断的风险。",
        "",
        "## 样例明细",
        "",
    ]
    for row in direct["results"][:20]:
        judgement = row.get("judgement", {})
        lines.append(
            f"- [{row['agent']}] {row['dataset']}/{row['case_id']}: "
            f"success={judgement.get('attack_success')} severity={judgement.get('severity')} "
            f"type={judgement.get('attack_type', '')} evidence={judgement.get('evidence', '')}"
        )

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({
        "direct_path": str(direct_path),
        "sandbox_path": str(sandbox_path),
        "report_path": str(report_path),
        "direct_summary": direct["summary"],
        "sandbox_ok": sandbox.get("ok"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
