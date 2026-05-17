import aiosqlite
import json
import os
import uuid
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "agentguard.db")
DB_PATH = os.path.normpath(DB_PATH)


async def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def _ensure_column(db, table: str, column: str, definition: str):
    cursor = await db.execute(f"PRAGMA table_info({table})")
    rows = await cursor.fetchall()
    existing = {row[1] for row in rows}
    if column not in existing:
        await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


async def init_db():
    db = await get_db()
    try:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS analysis_record (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trace_id TEXT,
                input_type TEXT,
                input_content TEXT,
                behavior_chain TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                risk_categories TEXT,
                matched_rules TEXT,
                policy_decision TEXT,
                reason TEXT,
                suggestion TEXT,
                previous_hash TEXT,
                record_hash TEXT,
                report_hash TEXT,
                created_at TEXT
            )
        """)
        await _ensure_column(db, "analysis_record", "defense_breaches", "TEXT DEFAULT '[]'")

        await db.execute("""
            CREATE TABLE IF NOT EXISTS agent_target (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                system_prompt TEXT DEFAULT '',
                api_schemas TEXT DEFAULT '[]',
                safety_constraints TEXT DEFAULT '[]',
                runtime_env TEXT DEFAULT '{}',
                access_mode TEXT DEFAULT 'callback',
                access_config TEXT DEFAULT '{}',
                created_at TEXT,
                updated_at TEXT
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_task (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                target_id TEXT NOT NULL,
                scan_mode TEXT DEFAULT 'standard',
                status TEXT DEFAULT 'pending',
                total_payloads INTEGER DEFAULT 0,
                completed_payloads INTEGER DEFAULT 0,
                vulnerabilities_found INTEGER DEFAULT 0,
                config TEXT DEFAULT '{}',
                summary TEXT DEFAULT '{}',
                started_at TEXT,
                completed_at TEXT,
                FOREIGN KEY (target_id) REFERENCES agent_target(target_id)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS attack_payload (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_id TEXT UNIQUE NOT NULL,
                category TEXT,
                title TEXT,
                severity TEXT DEFAULT 'medium',
                template TEXT,
                params TEXT DEFAULT '[]',
                mutations TEXT DEFAULT '[]',
                cwe_reference TEXT DEFAULT '',
                enabled INTEGER DEFAULT 1,
                created_at TEXT
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS fuzz_result (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                payload_id TEXT NOT NULL,
                variant TEXT NOT NULL,
                react_trace TEXT DEFAULT '{}',
                defense_breaches TEXT DEFAULT '[]',
                is_vulnerability INTEGER DEFAULT 0,
                vulnerability_severity TEXT,
                risk_score INTEGER DEFAULT 0,
                response_time_ms INTEGER DEFAULT 0,
                created_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_task(scan_id)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS evidence_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_type TEXT,
                record_ref TEXT,
                previous_hash TEXT,
                current_hash TEXT,
                created_at TEXT
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                case_id TEXT,
                payload_category TEXT,
                injection_point TEXT,
                mutations TEXT DEFAULT '[]',
                trace_id TEXT,
                risk_score REAL DEFAULT 0,
                risk_level TEXT,
                policy_action TEXT,
                breach_layers TEXT DEFAULT '[]',
                matched_rules TEXT DEFAULT '[]',
                record_hash TEXT,
                created_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_task(scan_id)
            )
        """)

        await db.commit()
    finally:
        await db.close()


# ── 原 analysis_record CRUD（保留不变）────────────────────────────

async def save_record(record: dict) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO analysis_record
            (trace_id, input_type, input_content, behavior_chain, risk_score, risk_level,
             risk_categories, matched_rules, defense_breaches, policy_decision, reason, suggestion,
             previous_hash, record_hash, report_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record["trace_id"],
                record["input_type"],
                record["input_content"],
                json.dumps(record.get("behavior_chain"), ensure_ascii=False),
                record["risk_score"],
                record["risk_level"],
                json.dumps(record.get("risk_categories"), ensure_ascii=False),
                json.dumps(record.get("matched_rules"), ensure_ascii=False),
                json.dumps(record.get("defense_breaches", []), ensure_ascii=False, cls=_SafeJSONEncoder),
                json.dumps(record.get("policy_decision"), ensure_ascii=False),
                record.get("reason", ""),
                record.get("suggestion", ""),
                record.get("previous_hash", ""),
                record.get("record_hash", ""),
                record.get("report_hash", ""),
                record.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_record(record_id: int) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM analysis_record WHERE id = ?", (record_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_dict(row)
    finally:
        await db.close()


async def get_records(limit: int = 50, offset: int = 0) -> list:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM analysis_record ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [_row_to_dict(row) for row in rows]
    finally:
        await db.close()


async def get_last_record_hash() -> str:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT record_hash FROM analysis_record ORDER BY id DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        if row and row[0]:
            return row[0]
        return ""
    finally:
        await db.close()



async def get_record_count() -> int:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM analysis_record")
        row = await cursor.fetchone()
        return row[0] if row else 0
    finally:
        await db.close()


async def get_record_by_trace_id(trace_id: str) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM analysis_record WHERE trace_id = ? ORDER BY id DESC LIMIT 1",
            (trace_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_dict(row)
    finally:
        await db.close()


async def mark_incomplete_scans_failed() -> int:
    db = await get_db()
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = await db.execute(
            "UPDATE scan_task SET status = 'failed', completed_at = ? WHERE status IN ('pending', 'running', 'paused')",
            (now,),
        )
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()


async def get_all_records() -> list:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM analysis_record ORDER BY id ASC")
        rows = await cursor.fetchall()
        return [_row_to_dict(row) for row in rows]
    finally:
        await db.close()


async def get_stats() -> dict:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM analysis_record")
        total = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT risk_level, COUNT(*) FROM analysis_record GROUP BY risk_level")
        risk_levels = dict(await cursor.fetchall())

        cursor = await db.execute("SELECT risk_categories FROM analysis_record")
        cat_rows = await cursor.fetchall()
        cat_dist = {}
        for row in cat_rows:
            try:
                cats = json.loads(row[0]) if row[0] else []
            except (json.JSONDecodeError, TypeError):
                cats = []
            for c in cats:
                cat_dist[c] = cat_dist.get(c, 0) + 1

        cursor = await db.execute("SELECT policy_decision FROM analysis_record")
        pol_rows = await cursor.fetchall()
        pol_dist = {}
        for row in pol_rows:
            try:
                pd = json.loads(row[0]) if row[0] else {}
            except (json.JSONDecodeError, TypeError):
                pd = {}
            action = pd.get("action", "unknown")
            pol_dist[action] = pol_dist.get(action, 0) + 1

        cursor = await db.execute(
            "SELECT id, risk_score, created_at FROM analysis_record ORDER BY id DESC LIMIT 20"
        )
        recent = [{"id": r[0], "risk_score": r[1], "created_at": r[2]} for r in await cursor.fetchall()]

        cursor = await db.execute("SELECT matched_rules FROM analysis_record")
        rule_rows = await cursor.fetchall()
        rule_dist = {}
        for row in rule_rows:
            try:
                rules = json.loads(row[0]) if row[0] else []
            except (json.JSONDecodeError, TypeError):
                rules = []
            for r in rules:
                name = r.get("name", "unknown")
                rule_dist[name] = rule_dist.get(name, 0) + 1
        top_rules = sorted(rule_dist.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_count": total,
            "risk_level_distribution": risk_levels,
            "risk_category_distribution": cat_dist,
            "policy_distribution": pol_dist,
            "recent_scores": recent,
            "top_rules": [{"name": n, "count": c} for n, c in top_rules],
        }
    finally:
        await db.close()


# ── agent_target CRUD ─────────────────────────────────────────────

async def save_target(target: dict) -> int:
    db = await get_db()
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = await db.execute(
            """INSERT INTO agent_target
            (target_id, name, system_prompt, api_schemas, safety_constraints,
             runtime_env, access_mode, access_config, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                target["target_id"],
                target["name"],
                target.get("system_prompt", ""),
                json.dumps(target.get("api_schemas", []), ensure_ascii=False),
                json.dumps(target.get("safety_constraints", []), ensure_ascii=False),
                json.dumps(target.get("runtime_env", {}), ensure_ascii=False),
                target.get("access_mode", "callback"),
                json.dumps(target.get("access_config", {}), ensure_ascii=False),
                now,
                now,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_target_by_target_id(target_id: str) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM agent_target WHERE target_id = ?", (target_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return _target_row_to_dict(row)
    finally:
        await db.close()


async def get_target_by_id(id: int) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM agent_target WHERE id = ?", (id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return _target_row_to_dict(row)
    finally:
        await db.close()


async def get_all_targets() -> list:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM agent_target ORDER BY id DESC")
        rows = await cursor.fetchall()
        return [_target_row_to_dict(row) for row in rows]
    finally:
        await db.close()


async def update_target(target_id: str, updates: dict) -> bool:
    db = await get_db()
    try:
        # 列名白名单，防止SQL注入
        ALLOWED_COLUMNS = {
            "name", "system_prompt", "api_schemas", "safety_constraints",
            "runtime_env", "access_mode", "access_config", "callback_url", "status"
        }
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sets = []
        vals = []
        for key, val in updates.items():
            if key not in ALLOWED_COLUMNS:
                continue
            if key in ("api_schemas", "safety_constraints", "runtime_env", "access_config"):
                val = json.dumps(val, ensure_ascii=False)
            sets.append(f"{key} = ?")
            vals.append(val)
        if not sets:
            return False
        sets.append("updated_at = ?")
        vals.append(now)
        vals.append(target_id)
        await db.execute(
            f"UPDATE agent_target SET {', '.join(sets)} WHERE target_id = ?", vals
        )
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_target(target_id: str) -> bool:
    db = await get_db()
    try:
        await db.execute("DELETE FROM agent_target WHERE target_id = ?", (target_id,))
        await db.commit()
        return True
    finally:
        await db.close()


# ── scan_task CRUD ────────────────────────────────────────────────

async def save_scan_task(task: dict) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO scan_task
            (scan_id, target_id, scan_mode, status, total_payloads,
             completed_payloads, vulnerabilities_found, config, summary,
             started_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task["scan_id"],
                task["target_id"],
                task.get("scan_mode", "standard"),
                task.get("status", "pending"),
                task.get("total_payloads", 0),
                task.get("completed_payloads", 0),
                task.get("vulnerabilities_found", 0),
                json.dumps(task.get("config", {}), ensure_ascii=False),
                json.dumps(task.get("summary", {}), ensure_ascii=False),
                task.get("started_at"),
                task.get("completed_at"),
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_scan_by_scan_id(scan_id: str) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM scan_task WHERE scan_id = ?", (scan_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return _scan_row_to_dict(row)
    finally:
        await db.close()


async def get_all_scans(target_id: str = None, limit: int = 50) -> list:
    db = await get_db()
    try:
        if target_id:
            cursor = await db.execute(
                "SELECT * FROM scan_task WHERE target_id = ? ORDER BY id DESC LIMIT ?",
                (target_id, limit),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM scan_task ORDER BY id DESC LIMIT ?", (limit,)
            )
        rows = await cursor.fetchall()
        return [_scan_row_to_dict(row) for row in rows]
    finally:
        await db.close()


async def update_scan_task(scan_id: str, updates: dict) -> bool:
    db = await get_db()
    try:
        sets = []
        vals = []
        for key, val in updates.items():
            if key in ("config", "summary"):
                val = json.dumps(val, ensure_ascii=False)
            sets.append(f"{key} = ?")
            vals.append(val)
        vals.append(scan_id)
        await db.execute(
            f"UPDATE scan_task SET {', '.join(sets)} WHERE scan_id = ?", vals
        )
        await db.commit()
        return True
    finally:
        await db.close()


# ── attack_payload CRUD ───────────────────────────────────────────

async def save_payload(payload: dict) -> int:
    db = await get_db()
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = await db.execute(
            """INSERT OR REPLACE INTO attack_payload
            (payload_id, category, title, severity, template, params, mutations,
             cwe_reference, enabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                payload["payload_id"],
                payload.get("category", ""),
                payload.get("title", ""),
                payload.get("severity", "medium"),
                payload.get("template", ""),
                json.dumps(payload.get("params", []), ensure_ascii=False),
                json.dumps(payload.get("mutations", []), ensure_ascii=False),
                payload.get("cwe_reference", ""),
                payload.get("enabled", 1),
                payload.get("created_at", now),
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_all_payloads(category: str = None) -> list:
    db = await get_db()
    try:
        if category:
            cursor = await db.execute(
                "SELECT * FROM attack_payload WHERE category = ? AND enabled = 1 ORDER BY id",
                (category,),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM attack_payload WHERE enabled = 1 ORDER BY id"
            )
        rows = await cursor.fetchall()
        return [_payload_row_to_dict(row) for row in rows]
    finally:
        await db.close()


async def get_payload_by_id(payload_id: str) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM attack_payload WHERE payload_id = ?", (payload_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return _payload_row_to_dict(row)
    finally:
        await db.close()


async def delete_payload(payload_id: str) -> bool:
    db = await get_db()
    try:
        await db.execute("DELETE FROM attack_payload WHERE payload_id = ?", (payload_id,))
        await db.commit()
        return True
    finally:
        await db.close()


async def get_payload_categories() -> list:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT category, COUNT(*) as cnt FROM attack_payload WHERE enabled = 1 GROUP BY category"
        )
        rows = await cursor.fetchall()
        return [{"category": r[0], "count": r[1]} for r in rows]
    finally:
        await db.close()


# ── fuzz_result CRUD ──────────────────────────────────────────────

class _SafeJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return str(obj)


async def save_fuzz_result(result: dict) -> int:
    db = await get_db()
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = await db.execute(
            """INSERT INTO fuzz_result
            (scan_id, payload_id, variant, react_trace, defense_breaches,
             is_vulnerability, vulnerability_severity, risk_score, response_time_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result["scan_id"],
                result["payload_id"],
                result["variant"],
                json.dumps(result.get("react_trace", {}), ensure_ascii=False, cls=_SafeJSONEncoder),
                json.dumps(result.get("defense_breaches", []), ensure_ascii=False, cls=_SafeJSONEncoder),
                result.get("is_vulnerability", 0),
                result.get("vulnerability_severity"),
                result.get("risk_score", 0),
                result.get("response_time_ms", 0),
                result.get("created_at", now),
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_results_by_scan_id(scan_id: str) -> list:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM fuzz_result WHERE scan_id = ? ORDER BY id", (scan_id,)
        )
        rows = await cursor.fetchall()
        return [_result_row_to_dict(row) for row in rows]
    finally:
        await db.close()


async def get_scan_stats(scan_id: str) -> dict:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT payload_id, is_vulnerability, vulnerability_severity, defense_breaches, react_trace, variant FROM fuzz_result WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        )
        rows = await cursor.fetchall()

        payload_summary = {}
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, None: 0}
        for row in rows:
            payload_id = row[0]
            is_vuln = bool(row[1])
            severity = row[2] or "low"
            breaches_raw = row[3]
            trace_raw = row[4]
            variant = row[5] or ""
            try:
                breaches = json.loads(breaches_raw) if breaches_raw else []
            except (json.JSONDecodeError, TypeError):
                breaches = []
            try:
                react_trace = json.loads(trace_raw) if trace_raw else {}
            except (json.JSONDecodeError, TypeError):
                react_trace = {}

            state = payload_summary.setdefault(payload_id, {
                "is_vulnerability": False,
                "severity": None,
                "layers": set(),
                "has_error": False,
                "has_success": False,
            })
            if is_vuln:
                state["is_vulnerability"] = True
                if severity_order.get(severity, 0) > severity_order.get(state["severity"], 0):
                    state["severity"] = severity
                for breach in breaches:
                    for layer in (breach.get("layer", "") or "").split("+"):
                        layer = layer.strip()
                        if layer:
                            state["layers"].add(layer)
            elif isinstance(react_trace, dict) and react_trace.get("error"):
                state["has_error"] = True
            elif variant.startswith("[ERROR]"):
                state["has_error"] = True
            else:
                state["has_success"] = True

        total = len(payload_summary)
        vulns = sum(1 for item in payload_summary.values() if item["is_vulnerability"])
        execution_errors = sum(
            1 for item in payload_summary.values()
            if item["has_error"] and not item["has_success"] and not item["is_vulnerability"]
        )
        severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        defense_layer_dist = {"L1": 0, "L2": 0, "L3": 0, "L4": 0, "L5": 0}
        for item in payload_summary.values():
            if item["is_vulnerability"] and item["severity"] in severity_dist:
                severity_dist[item["severity"]] += 1
            for layer in item["layers"]:
                if layer in defense_layer_dist:
                    defense_layer_dist[layer] += 1

        return {
            "total_results": total,
            "vulnerabilities_found": vulns,
            "execution_errors": execution_errors,
            "severity_distribution": severity_dist,
            "defense_layer_distribution": defense_layer_dist,
        }
    finally:
        await db.close()


# ── 辅助函数 ──────────────────────────────────────────────────────

def _row_to_dict(row) -> dict:
    d = dict(row)
    for key in ["behavior_chain", "risk_categories", "matched_rules", "defense_breaches", "policy_decision"]:
        if key in d and d[key]:
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


def _target_row_to_dict(row) -> dict:
    d = dict(row)
    for key in ["api_schemas", "safety_constraints", "runtime_env", "access_config"]:
        if key in d and d[key]:
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


def _scan_row_to_dict(row) -> dict:
    d = dict(row)
    for key in ["config", "summary"]:
        if key in d and d[key]:
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


def _payload_row_to_dict(row) -> dict:
    d = dict(row)
    for key in ["params", "mutations"]:
        if key in d and d[key]:
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    d["enabled"] = bool(d.get("enabled", 1))
    return d


def _result_row_to_dict(row) -> dict:
    d = dict(row)
    for key in ["react_trace", "defense_breaches"]:
        if key in d and d[key]:
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    d["is_vulnerability"] = bool(d.get("is_vulnerability", 0))
    return d
