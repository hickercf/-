from app.core.evidence_chain import append_evidence_record, verify_evidence_chain
import asyncio, json

async def test():
    record_json = {
        'input_type': 'task',
        'risk_score': 80,
        'risk_level': '高风险',
        'risk_categories': json.dumps(['提示词注入']),
        'policy_decision': json.dumps({'action': 'block', 'reason': '测试'}),
        'matched_rules': json.dumps([{'id': 'R005', 'name': 'PI'}]),
    }
    
    record_dict = {
        'input_type': 'task',
        'risk_score': 80,
        'risk_level': '高风险',
        'risk_categories': ['提示词注入'],
        'policy_decision': {'action': 'block', 'reason': '测试'},
        'matched_rules': [{'id': 'R005', 'name': 'PI'}],
    }
    
    h1 = await append_evidence_record('', record_json)
    h2 = await append_evidence_record('', record_dict)
    print("Hash from JSON string:", h1[:16])
    print("Hash from dict:       ", h2[:16])
    print("Hashes match:", h1 == h2)
    
    # Build chain
    h2_actual = await append_evidence_record(h1, record_dict)
    records = [
        {**record_json, 'record_hash': h1, 'id': 1},
        {**record_dict, 'record_hash': h2_actual, 'id': 2},
    ]
    result = await verify_evidence_chain(records)
    print("Chain valid:", result['valid'])
    print("Checked:", result['checked'])
    print("Errors:", len(result['errors']))

asyncio.run(test())
