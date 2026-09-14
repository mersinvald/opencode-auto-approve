"""Wait for a final asynchronous result in an isolated test audit directory."""
import json
import time

def permission_result(api, session_id, result, audit_root, timeout=120):
    if result['effect'] != 'ask':
        return result
    pending = api.call('GET', f'/api/session/{session_id}/permission')
    request = next((item for item in pending if item['id'] == result['id']), None)
    if request and not request.get('message', '').startswith('Automatic review ['):
        return result
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = [json.loads(line) for f in audit_root.glob('*.jsonl') for line in f.read_text().splitlines()]
        final = next((r for r in reversed(rows) if r.get('requestID') == result['id'] and
                      r.get('status') in ['allow', 'ask', 'native_reply', 'resolved']), None)
        if final:
            assert final['applied'] in ['allow', 'ask', 'deny'], final['code']
            return {**result, 'effect': final['applied']}
        time.sleep(.05)
    raise AssertionError('No final review result within the test deadline')
