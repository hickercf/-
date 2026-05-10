import aiosqlite
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "agentguard.db")
DB_PATH = os.path.normpath(DB_PATH)


async def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def init_db():
    db = await get_db()
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
    await db.commit()
    await db.close()


async def save_record(record: dict) -> int:
    db = await get_db()
    cursor = await db.execute(
        """INSERT INTO analysis_record
        (trace_id, input_type, input_content, behavior_chain, risk_score, risk_level,
         risk_categories, matched_rules, policy_decision, reason, suggestion,
         previous_hash, record_hash, report_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            record["trace_id"],
            record["input_type"],
            record["input_content"],
            json.dumps(record.get("behavior_chain"), ensure_ascii=False),
            record["risk_score"],
            record["risk_level"],
            json.dumps(record.get("risk_categories"), ensure_ascii=False),
            json.dumps(record.get("matched_rules"), ensure_ascii=False),
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
    record_id = cursor.lastrowid
    await db.close()
    return record_id


async def get_record(record_id: int) -> dict:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM analysis_record WHERE id = ?", (record_id,))
    row = await cursor.fetchone()
    await db.close()
    if row is None:
        return None
    return _row_to_dict(row)


async def get_records(limit: int = 50, offset: int = 0) -> list:
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM analysis_record ORDER BY id DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    rows = await cursor.fetchall()
    await db.close()
    return [_row_to_dict(row) for row in rows]


async def get_all_records() -> list:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM analysis_record ORDER BY id ASC")
    rows = await cursor.fetchall()
    await db.close()
    return [_row_to_dict(row) for row in rows]


async def get_stats() -> dict:
    db = await get_db()
    cursor = await db.execute("SELECT COUNT(*) FROM analysis_record")
    total = (await cursor.fetchone())[0]

    cursor = await db.execute("SELECT risk_level, COUNT(*) FROM analysis_record GROUP BY risk_level")
    risk_levels = dict(await cursor.fetchall())

    cursor = await db.execute("SELECT risk_categories FROM analysis_record")
    cat_rows = await cursor.fetchall()
    cat_dist = {}
    for row in cat_rows:
        cats = json.loads(row[0]) if row[0] else []
        for c in cats:
            cat_dist[c] = cat_dist.get(c, 0) + 1

    cursor = await db.execute("SELECT policy_decision FROM analysis_record")
    pol_rows = await cursor.fetchall()
    pol_dist = {}
    for row in pol_rows:
        pd = json.loads(row[0]) if row[0] else {}
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
        rules = json.loads(row[0]) if row[0] else []
        for r in rules:
            name = r.get("name", "unknown")
            rule_dist[name] = rule_dist.get(name, 0) + 1
    top_rules = sorted(rule_dist.items(), key=lambda x: x[1], reverse=True)[:10]

    await db.close()
    return {
        "total_count": total,
        "risk_level_distribution": risk_levels,
        "risk_category_distribution": cat_dist,
        "policy_distribution": pol_dist,
        "recent_scores": recent,
        "top_rules": [{"name": n, "count": c} for n, c in top_rules],
    }


def _row_to_dict(row) -> dict:
    d = dict(row)
    for key in ["behavior_chain", "risk_categories", "matched_rules", "policy_decision"]:
        if key in d and d[key]:
            d[key] = json.loads(d[key])
    return d
