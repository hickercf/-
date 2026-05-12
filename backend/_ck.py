import asyncio
from app.database.db import init_db, get_db, get_all_targets, get_all_scans, get_all_payloads, get_stats

async def check():
    await init_db()
    db = await get_db()
    cursor = await db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [r[0] for r in await cursor.fetchall() if r[0] != 'sqlite_sequence']
    await db.close()
    stats = await get_stats()
    targets = await get_all_targets()
    scans = await get_all_scans()
    payloads = await get_all_payloads()
    print('Tables: %d - %s' % (len(tables), tables))
    print('Records: %d | Targets: %d | Scans: %d | Payloads: %d' % (
        stats['total_count'], len(targets), len(scans), len(payloads)))

asyncio.run(check())
