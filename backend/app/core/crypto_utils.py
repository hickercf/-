import hashlib


def sm3_hash(data: str) -> str:
    try:
        from gmssl import sm3 as _sm3, func
        msg = data.encode("utf-8")
        return _sm3.sm3_hash(func.bytes_to_list(msg))
    except ImportError:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
