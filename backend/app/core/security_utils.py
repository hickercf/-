"""
security_utils.py — 安全工具函数

提供输入校验、SSRF 防护、路径遍历防护等安全功能。
"""
import re
import ipaddress
import os
from urllib.parse import urlparse


def is_safe_log_file_path(path: str) -> tuple:
    """
    校验日志文件路径是否安全
    
    返回: (is_safe: bool, error_message: str)
    """
    if not path:
        return False, "路径不能为空"
    
    # 禁止路径遍历
    if ".." in path or "~" in path:
        return False, "路径包含非法字符 (.. 或 ~)"
    
    # 禁止绝对路径（只允许相对路径）
    import os
    if os.path.isabs(path):
        return False, "不允许使用绝对路径"
    
    # 禁止空路径或仅包含特殊字符
    cleaned = path.strip()
    if not cleaned or cleaned.startswith("/") or cleaned.startswith("\\"):
        return False, "路径格式非法"
    
    return True, ""


def is_safe_callback_url(url: str) -> tuple:
    """
    校验回调 URL 是否安全（防止 SSRF）
    
    返回: (is_safe: bool, error_message: str)
    """
    if not url:
        return False, "URL 不能为空"
    
    # 只允许 http/https
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "只允许 HTTP/HTTPS 协议"
    
    hostname = parsed.hostname
    if not hostname:
        return False, "URL 格式错误"

    allow_local = os.getenv("ALLOW_LOCAL_CALLBACKS", "true").lower() == "true"
    if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
        if allow_local:
            return True, ""
        return False, "不允许访问本地地址"
    
    # 禁止 localhost
    if hostname.lower() == "0.0.0.0":
        return False, "不允许访问本地地址"
    
    # 检查是否是内网 IP
    try:
        ip = ipaddress.ip_address(hostname)
        # 检查是否是私有 IP 或特殊地址
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False, "不允许访问内网地址"
        # 禁止云元数据地址
        if str(ip) == "169.254.169.254":
            return False, "不允许访问云元数据服务"
    except ValueError:
        # 不是 IP，是域名，继续检查
        pass
    
    # 禁止常见的内网域名
    internal_patterns = [
        r"^169\.254\.",
        r"^10\.",
        r"^192\.168\.",
        r"^172\.(1[6-9]|2[0-9]|3[01])\.",
        r"\.local$",
        r"metadata\.google\.internal",
        r"^ip-10-",
        r"^ip-172-",
        r"^ip-192-168-",
    ]
    
    for pattern in internal_patterns:
        if re.search(pattern, hostname, re.IGNORECASE):
            return False, "不允许访问内网地址"
    
    return True, ""
