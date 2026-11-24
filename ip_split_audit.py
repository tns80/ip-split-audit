#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Split Audit · 代理分流一键体检工具
Zero-dependency CLI & HTML diagnostic tool to audit proxy split-tunneling
(Direct vs Proxy vs AI strategy groups), score your rules, and suggest fixes.

License: MIT
"""

import argparse
import bisect
import concurrent.futures
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

VERSION = "1.0.0"

# Ensure UTF-8 & ANSI color support on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
TIMEOUT = 6.0

# 主流开源中国大陆 IPv4 库 (多源自动兜底)
CN_IP_SOURCES = [
    (
        "gaoyifan/china-operator-ip (BGP 运营商汇总)",
        "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt",
    ),
    (
        "Loyalsoldier/geoip (IPIP+MaxMind CN)",
        "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt",
    ),
    (
        "17mon/china_ip_list (IPIP.net)",
        "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
    ),
]

AI_RESTRICTED_REGIONS = ("CN", "HK", "MO", "RU", "BY", "KP", "IR")


class Color:
    enabled = True

    @classmethod
    def wrap(cls, code: str, text: str) -> str:
        if not cls.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    @classmethod
    def bold(cls, t: str) -> str:
        return cls.wrap("1", t)

    @classmethod
    def dim(cls, t: str) -> str:
        return cls.wrap("2", t)

    @classmethod
    def green(cls, t: str) -> str:
        return cls.wrap("92", t)

    @classmethod
    def yellow(cls, t: str) -> str:
        return cls.wrap("93", t)

    @classmethod
    def red(cls, t: str) -> str:
        return cls.wrap("91", t)

    @classmethod
    def cyan(cls, t: str) -> str:
        return cls.wrap("96", t)

    @classmethod
    def magenta(cls, t: str) -> str:
        return cls.wrap("95", t)


@dataclass
class ProxyEnv:
    system_proxy_enabled: bool = False
    system_proxy_server: str = ""
    system_proxy_override: str = ""
    env_proxy: str = ""
    tun_adapters: List[str] = field(default_factory=list)
    fake_ip_detected: bool = False
    effective_proxy_url: Optional[str] = None
    mode_summary: str = ""


@dataclass
class TestResult:
    category: str
    name: str
    target: str
    expected: str  # "DIRECT" or "PROXY"
    route: str  # "PROXY", "DIRECT", "SUSPECT_PROXY", "SUSPECT_DIRECT", "FAILED", "UNKNOWN"
    method: str
    exit_ip: str = ""
    location: str = ""
    colo: str = ""
    resolved_ip: str = ""
    is_fake_ip: bool = False
    rtt_ms: Optional[float] = None
    direct_rtt_ms: Optional[float] = None
    http_status: Optional[int] = None
    cn_db_match: Optional[bool] = None
    match_expected: Optional[bool] = None
    preference_note: bool = False  # True for preference-dependent items like Apple Global / HK Baidu edge
    error: str = ""


@dataclass
class DimensionScore:
    key: str
    name: str
    score: int
    max_score: int
    summary: str


@dataclass
class DiagnosisItem:
    level: str  # "good", "warn", "error", "info"
    title: str
    detail: str
    suggestion: str = ""
    rule_snippet: List[str] = field(default_factory=list)


@dataclass
class AuditReport:
    total_score: int
    grade: str
    grade_emoji: str
    grade_tagline: str
    audit_mode: str  # "whitelist" or "blacklist"
    dimensions: List[DimensionScore]
    diagnosis: List[DiagnosisItem]
    ai_isolated: bool = False
    ai_exit_ips: List[str] = field(default_factory=list)
    general_exit_ips: List[str] = field(default_factory=list)


class CIDRDatabase:
    """Fast IPv4 CIDR lookup using sorted merged integer intervals."""

    def __init__(self, name: str = ""):
        self.name = name
        self.starts: List[int] = []
        self.ends: List[int] = []
        self.count = 0

    def load_lines(self, lines: List[str]) -> int:
        intervals = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or ":" in line:
                continue
            try:
                net = ipaddress.IPv4Network(line, strict=False)
                intervals.append((int(net.network_address), int(net.broadcast_address)))
            except ValueError:
                continue
        if not intervals:
            return 0
        intervals.sort()
        merged = [intervals[0]]
        for s, e in intervals[1:]:
            prev_s, prev_e = merged[-1]
            if s <= prev_e + 1:
                merged[-1] = (prev_s, max(prev_e, e))
            else:
                merged.append((s, e))
        self.starts = [x[0] for x in merged]
        self.ends = [x[1] for x in merged]
        self.count = len(intervals)
        return self.count

    def contains(self, ip_str: str) -> Optional[bool]:
        if not self.starts or not ip_str:
            return None
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.version != 4:
                return None
            val = int(ip_obj)
        except ValueError:
            return None
        idx = bisect.bisect_right(self.starts, val) - 1
        if idx >= 0 and val <= self.ends[idx]:
            return True
        return False


def is_valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip())
        return True
    except ValueError:
        return False


def is_fake_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version == 4:
            return ip_obj in ipaddress.IPv4Network("198.18.0.0/15")
    except ValueError:
        pass
    return False


def is_private_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return False


def normalize_proxy_url(raw: str) -> Optional[str]:
    if not raw:
        return None
    raw = raw.strip()
    if "=" in raw:
        parts = {}
        for item in raw.split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                parts[k.strip().lower()] = v.strip()
        raw = parts.get("https") or parts.get("http") or next(iter(parts.values()), "")
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    return raw


def detect_proxy_env(explicit_proxy: Optional[str] = None) -> ProxyEnv:
    env = ProxyEnv()

    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        val = os.environ.get(key)
        if val:
            env.env_proxy = val
            break

    if sys.platform == "win32":
        try:
            import winreg

            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                try:
                    enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                    env.system_proxy_enabled = bool(enabled)
                except FileNotFoundError:
                    pass
                try:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    env.system_proxy_server = str(server)
                except FileNotFoundError:
                    pass
                try:
                    override, _ = winreg.QueryValueEx(key, "ProxyOverride")
                    env.system_proxy_override = str(override)
                except FileNotFoundError:
                    pass
        except Exception:
            pass

        try:
            out = subprocess.check_output(["ipconfig"], stderr=subprocess.DEVNULL, timeout=3)
            text = out.decode("gbk", errors="ignore")
            keywords = (
                "meta", "mihomo", "clash", "sing-box", "singbox",
                "wintun", "utun", "nekoray", "v2ray", "wireguard",
                "tailscale", "flclash", "surge", "tun",
            )
            for line in text.splitlines():
                if line.strip().endswith(":") and not line.startswith(" "):
                    lower = line.lower()
                    if any(k in lower for k in keywords) or "198.18." in lower:
                        env.tun_adapters.append(line.strip().rstrip(":"))
            if "198.18." in text:
                env.fake_ip_detected = True
        except Exception:
            pass

    if explicit_proxy:
        env.effective_proxy_url = normalize_proxy_url(explicit_proxy)
    elif env.env_proxy:
        env.effective_proxy_url = normalize_proxy_url(env.env_proxy)
    elif env.system_proxy_enabled and env.system_proxy_server:
        env.effective_proxy_url = normalize_proxy_url(env.system_proxy_server)

    try:
        infos = socket.getaddrinfo("www.google.com", 443, socket.AF_INET)
        if infos and is_fake_ip(infos[0][4][0]):
            env.fake_ip_detected = True
    except Exception:
        pass

    modes = []
    if env.effective_proxy_url:
        modes.append(f"系统/指定代理 ({env.effective_proxy_url})")
    if env.tun_adapters:
        modes.append(f"TUN 虚拟网卡 ({', '.join(env.tun_adapters)})")
    if env.fake_ip_detected:
        modes.append("Fake-IP DNS / TUN 模式")
    if not modes:
        modes.append("无显式系统代理 (可能为旁路由/透明代理/纯直连)")
    env.mode_summary = " + ".join(modes)
    return env


def make_opener(proxy_url: Optional[str], bypass_proxy: bool = False) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    if bypass_proxy:
        proxy_handler = urllib.request.ProxyHandler({})
    elif proxy_url:
        proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    else:
        proxy_handler = urllib.request.ProxyHandler()
    return urllib.request.build_opener(proxy_handler, https_handler)


def http_get(
    url: str,
    proxy_url: Optional[str] = None,
    bypass_proxy: bool = False,
    timeout: float = TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_bytes: int = 65536,
) -> Tuple[Optional[int], bytes, float, str]:
    opener = make_opener(proxy_url, bypass_proxy=bypass_proxy)
    req_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = resp.getcode()
            body = resp.read(max_bytes)
            rtt = (time.perf_counter() - t0) * 1000.0
            return status, body, rtt, ""
    except urllib.error.HTTPError as e:
        rtt = (time.perf_counter() - t0) * 1000.0
        try:
            body = e.read(max_bytes)
        except Exception:
            body = b""
        return e.code, body, rtt, f"HTTP {e.code}"
    except Exception as e:
        rtt = (time.perf_counter() - t0) * 1000.0
        return None, b"", rtt, str(e)


def parse_trace_text(text: str) -> Tuple[str, str]:
    ip_val = ""
    colo_val = ""
    for line in text.splitlines():
        if line.startswith("ip="):
            ip_val = line.split("=", 1)[1].strip()
        elif line.startswith("colo="):
            colo_val = line.split("=", 1)[1].strip()
    return ip_val, colo_val


def load_or_sync_cn_db(proxy_url: Optional[str], skip_sync: bool = False) -> CIDRDatabase:
    db = CIDRDatabase()
    cache_file = DATA_DIR / "cn_ip_list.txt"
    meta_file = DATA_DIR / "cn_ip_meta.json"

    if cache_file.exists() and (skip_sync or (time.time() - cache_file.stat().st_mtime < 86400)):
        lines = cache_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        src_name = "本地缓存"
        if meta_file.exists():
            try:
                src_name = json.loads(meta_file.read_text(encoding="utf-8")).get("source", src_name)
            except Exception:
                pass
        if db.load_lines(lines) > 0:
            db.name = f"{src_name} (缓存)"
            return db

    if not skip_sync:
        for src_name, url in CN_IP_SOURCES:
            status, body, _, _ = http_get(url, proxy_url=proxy_url, timeout=8.0, max_bytes=2 * 1024 * 1024)
            if status == 200 and body:
                text = body.decode("utf-8", errors="ignore")
                cnt = db.load_lines(text.splitlines())
                if cnt > 1000:
                    db.name = src_name
                    cache_file.write_text(text, encoding="utf-8")
                    meta_file.write_text(
                        json.dumps(
                            {"source": src_name, "url": url, "count": cnt, "updated": datetime.now().isoformat()},
                            ensure_ascii=False,
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
                    return db
    return db


def resolve_host(host: str) -> Tuple[str, bool]:
    if is_valid_ip(host):
        return host, is_fake_ip(host)
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET)
        if infos:
            ip = infos[0][4][0]
            return ip, is_fake_ip(ip)
    except Exception:
        pass
    return "", False


def tcp_tls_probe_direct(
    ip: str, port: int, timeout: float = 4.0, sni: Optional[str] = None, proto: str = "auto"
) -> Tuple[bool, Optional[float], str]:
    if proto == "auto":
        proto = "tls" if port == 443 else "tcp"
    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        if proto == "tls":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssock = ctx.wrap_socket(sock, server_hostname=sni or ip)
            ssock.close()
        elif proto == "http_raw":
            sock.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode("ascii"))
            resp = sock.recv(64)
            sock.close()
            if not resp:
                return False, None, "Empty remote reply"
        else:
            sock.close()
        rtt = (time.perf_counter() - t0) * 1000.0
        return True, rtt, ""
    except Exception as e:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        return False, None, str(e)


def tcp_tls_probe_via_http_proxy(
    ip: str, port: int, proxy_url: str, timeout: float = 5.0, sni: Optional[str] = None, proto: str = "auto"
) -> Tuple[bool, Optional[float], str]:
    if proto == "auto":
        proto = "tls" if port == 443 else "tcp"
    parsed = urllib.parse.urlparse(proxy_url)
    p_host = parsed.hostname or "127.0.0.1"
    p_port = parsed.port or 7890
    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((p_host, p_port), timeout=timeout)
        sock.settimeout(timeout)
        req = f"CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
        sock.sendall(req.encode("ascii"))
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(1024)
            if not chunk:
                break
            resp += chunk
        first_line = resp.split(b"\r\n", 1)[0].decode("ascii", errors="ignore")
        if " 200 " not in first_line:
            sock.close()
            return False, None, f"Proxy CONNECT failed: {first_line}"
        if proto == "tls":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssock = ctx.wrap_socket(sock, server_hostname=sni or ip)
            ssock.close()
        elif proto == "http_raw":
            sock.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode("ascii"))
            data = sock.recv(64)
            sock.close()
            if not data:
                return False, None, "Empty remote reply"
        else:
            sock.close()
        rtt = (time.perf_counter() - t0) * 1000.0
        return True, rtt, ""
    except Exception as e:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        return False, None, str(e)


# ==============================================================================
# Test Matrix (86 Mainstream Targets across 8 Categories)
# ==============================================================================

ECHO_CN_TESTS = [
    ("国内 IP 回显", "IPIP.net", "https://myip.ipip.net/json", "json_ipip", "DIRECT"),
    ("国内 IP 回显", "腾讯视频 IP", "https://vv.video.qq.com/checktime?otype=json", "regex_ip", "DIRECT"),
    ("国内 IP 回显", "腾讯新闻 IP", "https://r.inews.qq.com/api/ip2city", "json_qq", "DIRECT"),
    ("国内 IP 回显", "Bilibili IP", "https://api.live.bilibili.com/xlive/web-room/v1/index/getIpInfo", "json_bili", "DIRECT"),
    ("国内 IP 回显", "太平洋 PConline", "https://whois.pconline.com.cn/ipJson.jsp?json=true", "json_pconline", "DIRECT"),
    ("国内 IP 回显", "花生壳 Oray", "https://ddns.oray.com/checkip", "regex_ip", "DIRECT"),
    ("国内 IP 回显", "3322.net", "http://ip.3322.net", "plain_ip", "DIRECT"),
    ("国内 IP 回显", "cip.cc", "http://cip.cc", "cip_cc", "DIRECT"),
]

ECHO_GLOBAL_TESTS = [
    ("海外 IP 回显", "Cloudflare (纯IP 1.1.1.1)", "https://1.1.1.1/cdn-cgi/trace", "cf_trace", "PROXY"),
    ("海外 IP 回显", "Cloudflare (纯IP 1.0.0.1)", "https://1.0.0.1/cdn-cgi/trace", "cf_trace", "PROXY"),
    ("海外 IP 回显", "Cloudflare (域名)", "https://www.cloudflare.com/cdn-cgi/trace", "cf_trace", "PROXY"),
    ("海外 IP 回显", "IPInfo.io", "https://ipinfo.io/json", "json_ipinfo", "PROXY"),
    ("海外 IP 回显", "IP.SB", "https://api.ip.sb/geoip", "json_ipsb", "PROXY"),
    ("海外 IP 回显", "IPify (IPv4)", "https://api4.ipify.org?format=json", "json_ipify", "PROXY"),
    ("海外 IP 回显", "AWS CheckIP", "https://checkip.amazonaws.com", "plain_ip", "PROXY"),
    ("海外 IP 回显", "IP-API", "http://ip-api.com/json/?lang=zh-CN", "json_ipapi", "PROXY"),
    ("海外 IP 回显", "icanhazip", "https://ipv4.icanhazip.com", "plain_ip", "PROXY"),
    ("海外 IP 回显", "ifconfig.me", "https://ifconfig.me/ip", "plain_ip", "PROXY"),
    ("海外 IP 回显", "ident.me (EU)", "https://v4.ident.me", "plain_ip", "PROXY"),
]

AI_CORE_NAMES = {"ChatGPT (OpenAI)", "OpenAI 主站", "OpenAI API", "Claude (Anthropic)", "Perplexity AI", "Gemini"}

SERVICE_TRACE_TESTS = [
    ("AI/热门服务出口", "ChatGPT (OpenAI)", "https://chatgpt.com/cdn-cgi/trace", "PROXY"),
    ("AI/热门服务出口", "OpenAI 主站", "https://openai.com/cdn-cgi/trace", "PROXY"),
    ("AI/热门服务出口", "OpenAI API", "https://api.openai.com/cdn-cgi/trace", "PROXY"),
    ("AI/热门服务出口", "Claude (Anthropic)", "https://claude.ai/cdn-cgi/trace", "PROXY"),
    ("AI/热门服务出口", "Perplexity AI", "https://www.perplexity.ai/cdn-cgi/trace", "PROXY"),
    ("AI/热门服务出口", "GitLab", "https://gitlab.com/cdn-cgi/trace", "PROXY"),
    ("AI/热门服务出口", "Notion", "https://www.notion.so/cdn-cgi/trace", "PROXY"),
    ("AI/热门服务出口", "npm Registry", "https://registry.npmjs.org/cdn-cgi/trace", "PROXY"),
    ("AI/热门服务出口", "Medium", "https://medium.com/cdn-cgi/trace", "PROXY"),
    ("AI/热门服务出口", "Canva", "https://www.canva.com/cdn-cgi/trace", "PROXY"),
]

CN_DOMAIN_TESTS = [
    ("国内主流网站", "百度", "https://www.baidu.com", "DIRECT"),
    ("国内主流网站", "淘宝", "https://www.taobao.com", "DIRECT"),
    ("国内主流网站", "京东", "https://www.jd.com", "DIRECT"),
    ("国内主流网站", "Bilibili", "https://www.bilibili.com", "DIRECT"),
    ("国内主流网站", "知乎", "https://www.zhihu.com", "DIRECT"),
    ("国内主流网站", "网易", "https://www.163.com", "DIRECT"),
    ("国内主流网站", "阿里云", "https://www.aliyun.com", "DIRECT"),
    ("国内主流网站", "腾讯云", "https://cloud.tencent.com", "DIRECT"),
    ("国内主流网站", "Apple 中国", "https://www.apple.com.cn", "DIRECT"),
    ("国内主流网站", "Bing 中国", "https://cn.bing.com", "DIRECT"),
]

GLOBAL_DOMAIN_TESTS = [
    ("海外主流服务", "Google", "https://www.google.com/generate_204", "PROXY"),
    ("海外主流服务", "YouTube", "https://www.youtube.com/generate_204", "PROXY"),
    ("海外主流服务", "Gemini", "https://gemini.google.com", "PROXY"),
    ("海外主流服务", "Discord API", "https://discord.com/api/v10/gateway", "PROXY"),
    ("海外主流服务", "GitHub", "https://github.com", "PROXY"),
    ("海外主流服务", "GitHub Raw", "https://raw.githubusercontent.com", "PROXY"),
    ("海外主流服务", "X / Twitter", "https://x.com", "PROXY"),
    ("海外主流服务", "Telegram Web", "https://web.telegram.org", "PROXY"),
    ("海外主流服务", "Netflix", "https://www.netflix.com", "PROXY"),
    ("海外主流服务", "Spotify", "https://open.spotify.com", "PROXY"),
    ("海外主流服务", "Wikipedia", "https://en.wikipedia.org", "PROXY"),
    ("海外主流服务", "Reddit", "https://www.reddit.com", "PROXY"),
    ("海外主流服务", "HuggingFace", "https://huggingface.co", "PROXY"),
    ("海外主流服务", "Docker Hub", "https://hub.docker.com", "PROXY"),
    ("海外主流服务", "Apple Global", "https://www.apple.com", "PROXY"),
]

# 纯 IP 段测试 (全 443/80 端口，彻底避开 dns-hijack: any:53 干扰; 3 次采样取中位数)
PURE_IP_TESTS = [
    # 中国大陆 IP & 易误判新段/运营商/云/教育网 (预期: DIRECT)
    ("纯IP-国内及易误判段", "阿里 DoH 主 (223.5段 CN)", "223.5.5.5", 443, "DIRECT", "dns.alidns.com", "tls"),
    ("纯IP-国内及易误判段", "阿里 DoH 备 (223.6段 CN)", "223.6.6.6", 443, "DIRECT", "dns.alidns.com", "tls"),
    ("纯IP-国内及易误判段", "腾讯 DoH 1.12段 (易误判!)", "1.12.12.12", 443, "DIRECT", "doh.pub", "tls"),
    ("纯IP-国内及易误判段", "腾讯 DoH 120.53段 (CN)", "120.53.53.53", 443, "DIRECT", "doh.pub", "tls"),
    ("纯IP-国内及易误判段", "百度现网 223.109段 (CN)", "223.109.82.212", 443, "DIRECT", "www.baidu.com", "tls"),
    ("纯IP-国内及易误判段", "淘宝 111.3段 (CN)", "111.3.85.58", 443, "DIRECT", "www.taobao.com", "tls"),
    ("纯IP-国内及易误判段", "阿里云杭州 118.178段 (CN)", "118.178.90.7", 443, "DIRECT", "ddns.oray.com", "tls"),
    ("纯IP-国内及易误判段", "腾讯云 117.163段 (CN)", "117.163.57.177", 443, "DIRECT", "cloud.tencent.com", "tls"),
    ("纯IP-国内及易误判段", "清华 TUNA 教育网 (101.6段)", "101.6.15.130", 443, "DIRECT", "mirrors.tuna.tsinghua.edu.cn", "tls"),
    ("纯IP-国内及易误判段", "中科大 USTC 教育网 (202.38段)", "202.38.95.110", 443, "DIRECT", "mirrors.ustc.edu.cn", "tls"),
    ("纯IP-国内及易误判段", "360 DoH 101.198段 (易误判!)", "101.198.198.198", 443, "DIRECT", "doh.360.cn", "tls"),
    ("纯IP-国内及易误判段", "京东 112.16段 (CN)", "112.16.230.65", 443, "DIRECT", "www.jd.com", "tls"),
    # 港澳台 / 亚太纯 IP 段 (全部 443 TLS，避开 53 端口劫持，预期: PROXY)
    ("纯IP-港澳台/亚太", "台湾 Quad101 主 (101.101段)", "101.101.101.101", 443, "PROXY", "dns.twnic.tw", "tls"),
    ("纯IP-港澳台/亚太", "台湾 Quad101 备 (101.102段)", "101.102.103.104", 443, "PROXY", "dns.twnic.tw", "tls"),
    ("纯IP-港澳台/亚太", "日本 IIJ DoH 主 (103.2段)", "103.2.57.5", 443, "PROXY", "public.dns.iij.jp", "tls"),
    ("纯IP-港澳台/亚太", "日本 IIJ DoH 备 (103.2段)", "103.2.57.6", 443, "PROXY", "public.dns.iij.jp", "tls"),
    ("纯IP-港澳台/亚太", "香港大学 HKU (147.8段 HK)", "147.8.2.58", 443, "PROXY", "www.hku.hk", "tls"),
    ("纯IP-港澳台/亚太", "香港百度边缘 (103.235段)", "103.235.46.40", 443, "PROXY", "www.baidu.com", "tls"),
    # 海外公共 / CDN / Telegram / GitHub / Meta 纯 IP (预期: PROXY)
    ("纯IP-海外主流ASN", "Google DNS (US)", "8.8.8.8", 443, "PROXY", "dns.google", "tls"),
    ("纯IP-海外主流ASN", "Google DNS 备 (US)", "8.8.4.4", 443, "PROXY", "dns.google", "tls"),
    ("纯IP-海外主流ASN", "Cloudflare (1.1.1.1)", "1.1.1.1", 443, "PROXY", None, "tls"),
    ("纯IP-海外主流ASN", "Cloudflare Edge (104.18段)", "104.18.32.7", 443, "PROXY", "www.cloudflare.com", "tls"),
    ("纯IP-海外主流ASN", "Quad9 DNS", "9.9.9.9", 443, "PROXY", "dns.quad9.net", "tls"),
    ("纯IP-海外主流ASN", "OpenDNS (Cisco)", "208.67.222.222", 443, "PROXY", "doh.opendns.com", "tls"),
    ("纯IP-海外主流ASN", "Telegram DC1 (Miami)", "149.154.175.53", 80, "PROXY", None, "http_raw"),
    ("纯IP-海外主流ASN", "Telegram DC2 (Amsterdam)", "149.154.167.51", 80, "PROXY", None, "http_raw"),
    ("纯IP-海外主流ASN", "Telegram DC3 (Miami)", "149.154.175.100", 80, "PROXY", None, "http_raw"),
    ("纯IP-海外主流ASN", "Telegram DC4 (Amsterdam)", "149.154.167.91", 80, "PROXY", None, "http_raw"),
    ("纯IP-海外主流ASN", "Telegram DC5 (Singapore)", "91.108.56.130", 80, "PROXY", None, "http_raw"),
    ("纯IP-海外主流ASN", "GitHub (US)", "140.82.112.4", 443, "PROXY", "github.com", "tls"),
    ("纯IP-海外主流ASN", "Fastly CDN", "151.101.1.69", 443, "PROXY", "www.fastly.com", "tls"),
    ("纯IP-海外主流ASN", "Meta / Facebook (US)", "157.240.1.35", 443, "PROXY", "www.facebook.com", "tls"),
]

# Items that are legitimately preference-dependent (do not penalize score)
PREFERENCE_ITEM_NAMES = {"Apple Global", "香港百度边缘 (103.235段)"}


def parse_echo_response(parser: str, body: bytes) -> Tuple[str, str, str]:
    if not body:
        return "", "", ""
    try:
        if parser == "json_pconline":
            text = body.decode("gbk", errors="ignore").strip()
            data = json.loads(text)
            return data.get("ip", "").strip(), data.get("addr", "").strip(), ""
        text = body.decode("utf-8", errors="ignore").strip()
        if parser == "cf_trace":
            ip_val, colo_val = parse_trace_text(text)
            return ip_val, "", colo_val
        elif parser == "plain_ip":
            first = text.splitlines()[0].strip()
            if is_valid_ip(first):
                return first, "", ""
        elif parser == "regex_ip":
            m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
            if m and is_valid_ip(m.group(1)):
                return m.group(1), "", ""
        elif parser == "cip_cc":
            ip_m = re.search(r"IP\s*:\s*(\S+)", text)
            loc_m = re.search(r"地址\s*:\s*(.+)", text)
            return (ip_m.group(1).strip() if ip_m else ""), (loc_m.group(1).strip() if loc_m else ""), ""
        elif parser == "json_ipip":
            data = json.loads(text).get("data", {})
            loc = " ".join([x for x in data.get("location", []) if x])
            return data.get("ip", "").strip(), loc, ""
        elif parser == "json_qq":
            data = json.loads(text)
            loc = " ".join(filter(None, [data.get("country"), data.get("province"), data.get("city")]))
            return data.get("ip", "").strip(), loc, ""
        elif parser == "json_bili":
            data = json.loads(text).get("data", {})
            loc = " ".join(filter(None, [data.get("country"), data.get("province"), data.get("city"), data.get("isp")]))
            return data.get("addr", "").strip(), loc, ""
        elif parser == "json_ipinfo":
            data = json.loads(text)
            loc = " ".join(filter(None, [data.get("country"), data.get("city"), data.get("org")]))
            return data.get("ip", "").strip(), loc, ""
        elif parser == "json_ipsb":
            data = json.loads(text)
            loc = " ".join(filter(None, [data.get("country_code"), data.get("country"), data.get("organization")]))
            return data.get("ip", "").strip(), loc, ""
        elif parser == "json_ipify":
            data = json.loads(text)
            return data.get("ip", "").strip(), "", ""
        elif parser == "json_ipapi":
            data = json.loads(text)
            loc = " ".join(filter(None, [data.get("countryCode"), data.get("country"), data.get("city"), data.get("isp")]))
            return data.get("query", "").strip(), loc, ""
    except Exception:
        pass
    try:
        text = body.decode("utf-8", errors="ignore")
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
        if m and is_valid_ip(m.group(1)):
            return m.group(1), "", ""
    except Exception:
        pass
    return "", "", ""


def run_echo_test(
    category: str, name: str, url: str, parser: str, expected: str,
    proxy_url: Optional[str], cn_db: CIDRDatabase
) -> TestResult:
    host = urllib.parse.urlparse(url).hostname or ""
    res_ip, fake = resolve_host(host)
    headers = None
    if parser == "cip_cc":
        headers = {"User-Agent": "curl/8.5.0"}
    elif parser == "json_ipinfo":
        headers = {"User-Agent": "curl/8.5.0", "Accept": "application/json"}
    status, body, rtt, err = http_get(url, proxy_url=proxy_url, headers=headers)
    exit_ip, loc, colo = parse_echo_response(parser, body)
    in_cn = cn_db.contains(exit_ip) if exit_ip else None
    return TestResult(
        category=category, name=name, target=url, expected=expected,
        route="UNKNOWN" if exit_ip else "FAILED", method="出口IP比对",
        exit_ip=exit_ip, location=loc, colo=colo, resolved_ip=res_ip, is_fake_ip=fake,
        rtt_ms=round(rtt, 1) if status is not None else None, http_status=status,
        cn_db_match=in_cn, error=err if not exit_ip else "",
    )


def run_service_trace_test(
    category: str, name: str, url: str, expected: str,
    proxy_url: Optional[str], cn_db: CIDRDatabase
) -> TestResult:
    host = urllib.parse.urlparse(url).hostname or ""
    res_ip, fake = resolve_host(host)
    status, body, rtt, err = http_get(url, proxy_url=proxy_url)
    exit_ip, colo = parse_trace_text(body.decode("utf-8", errors="ignore"))
    in_cn = cn_db.contains(exit_ip) if exit_ip else None
    return TestResult(
        category=category, name=name, target=url, expected=expected,
        route="UNKNOWN" if exit_ip else "FAILED", method="CF Trace 出口IP",
        exit_ip=exit_ip, colo=colo, resolved_ip=res_ip, is_fake_ip=fake,
        rtt_ms=round(rtt, 1) if status is not None else None, http_status=status,
        cn_db_match=in_cn, error=err if not exit_ip else "",
    )


def run_domain_test(
    category: str, name: str, url: str, expected: str,
    proxy_env: ProxyEnv, cn_db: CIDRDatabase
) -> TestResult:
    host = urllib.parse.urlparse(url).hostname or ""
    res_ip, fake = resolve_host(host)
    status, _, rtt, err = http_get(url, proxy_url=proxy_env.effective_proxy_url, max_bytes=4096)

    direct_status = None
    direct_rtt = None
    if proxy_env.effective_proxy_url and not proxy_env.tun_adapters:
        direct_status, _, d_rtt, _ = http_get(url, bypass_proxy=True, timeout=3.5, max_bytes=2048)
        if direct_status is not None:
            direct_rtt = round(d_rtt, 1)

    in_cn = cn_db.contains(res_ip) if (res_ip and not fake) else None
    route = "FAILED"
    method = "连通性/延迟分析"

    if status is not None:
        if proxy_env.effective_proxy_url and not proxy_env.tun_adapters:
            if direct_status is None:
                route = "PROXY"
                method = "直连失败/代理成功"
            else:
                if expected == "DIRECT":
                    if rtt <= max(direct_rtt * 1.8, direct_rtt + 80):
                        route = "DIRECT"
                        method = "延迟与直连一致"
                    else:
                        route = "SUSPECT_PROXY"
                        method = f"经代理延迟显著升高({rtt:.0f}ms vs 直连{direct_rtt:.0f}ms)"
                else:
                    if fake:
                        route = "PROXY"
                        method = "Fake-IP 接管"
                    elif rtt < direct_rtt - 50 or rtt > direct_rtt + 80:
                        route = "PROXY"
                        method = f"经代理路径不同({rtt:.0f}ms vs 直连{direct_rtt:.0f}ms)"
                    else:
                        route = "SUSPECT_DIRECT"
                        method = "直连亦可达(无出口IP)"
        else:
            if expected == "PROXY":
                blocked_hosts = (
                    "google.com", "youtube.com", "gemini.google.com", "discord.com",
                    "x.com", "web.telegram.org", "netflix.com", "wikipedia.org",
                    "reddit.com", "huggingface.co", "raw.githubusercontent.com",
                    "hub.docker.com", "spotify.com",
                )
                if any(b in host for b in blocked_hosts):
                    route = "PROXY"
                    method = "受限站点可达" + ("+FakeIP" if fake else "")
                elif fake:
                    if rtt < 200:
                        route = "SUSPECT_DIRECT"
                        method = f"Fake-IP接管但极低延迟({rtt:.0f}ms,内核直连/国内CDN)"
                    else:
                        route = "PROXY"
                        method = f"Fake-IP接管+海外延迟({rtt:.0f}ms)"
                else:
                    route = "SUSPECT_PROXY" if rtt > 350 else "SUSPECT_DIRECT"
                    method = f"TUN可达({rtt:.0f}ms)"
            else:
                if fake:
                    route = "SUSPECT_PROXY"
                    method = "国内站命中Fake-IP(需关注)"
                elif rtt < 250 and (in_cn is True or in_cn is None):
                    route = "DIRECT"
                    method = "国内IP低延迟直连"
                elif rtt >= 450:
                    route = "SUSPECT_PROXY"
                    method = f"国内站点高延迟({rtt:.0f}ms)"
                else:
                    route = "DIRECT"
                    method = f"正常访问({rtt:.0f}ms)"

    return TestResult(
        category=category, name=name, target=url, expected=expected,
        route=route, method=method, resolved_ip=res_ip, is_fake_ip=fake,
        rtt_ms=round(rtt, 1) if status is not None else None, direct_rtt_ms=direct_rtt,
        http_status=status, cn_db_match=in_cn,
        preference_note=(name in PREFERENCE_ITEM_NAMES),
        error=err if status is None else "",
    )


def run_pure_ip_test(
    category: str, name: str, ip: str, port: int, expected: str,
    sni: Optional[str], proto: str, proxy_env: ProxyEnv, cn_db: CIDRDatabase
) -> TestResult:
    in_cn = cn_db.contains(ip)
    target_str = f"{ip}:{port}"
    pref = name in PREFERENCE_ITEM_NAMES

    if ip in ("1.1.1.1", "1.0.0.1") and port == 443:
        status, body, rtt, _ = http_get(f"https://{ip}/cdn-cgi/trace", proxy_url=proxy_env.effective_proxy_url)
        exit_ip, colo = parse_trace_text(body.decode("utf-8", errors="ignore"))
        if exit_ip:
            return TestResult(
                category=category, name=name, target=target_str, expected=expected,
                route="UNKNOWN", method="纯IP Trace出口比对", exit_ip=exit_ip, colo=colo,
                resolved_ip=ip, rtt_ms=round(rtt, 1), http_status=status, cn_db_match=in_cn,
                preference_note=pref,
            )

    if proxy_env.effective_proxy_url and not proxy_env.tun_adapters:
        p_ok, p_rtt, p_err = tcp_tls_probe_via_http_proxy(ip, port, proxy_env.effective_proxy_url, sni=sni, proto=proto)
        d_ok, d_rtt, _ = tcp_tls_probe_direct(ip, port, timeout=3.0, sni=sni, proto=proto)
        if not p_ok:
            route, method, err = "FAILED", "代理连接失败", p_err
        elif not d_ok and p_ok:
            route, method, err = "PROXY", "直连不可达/代理成功", ""
        else:
            err = ""
            if expected == "DIRECT":
                if p_rtt <= max(d_rtt * 2.0, d_rtt + 70):
                    route, method = "DIRECT", f"代理内核直连({p_rtt:.0f}ms≈直连{d_rtt:.0f}ms)"
                else:
                    route, method = "SUSPECT_PROXY", f"疑似绕路({p_rtt:.0f}ms vs 直连{d_rtt:.0f}ms)"
            else:
                if p_rtt > d_rtt + 70 or p_rtt < d_rtt - 50:
                    route, method = "PROXY", f"延迟特征符合代理({p_rtt:.0f}ms vs 直连{d_rtt:.0f}ms)"
                else:
                    route, method = "SUSPECT_DIRECT", f"直连亦通({p_rtt:.0f}ms≈直连{d_rtt:.0f}ms)"
        return TestResult(
            category=category, name=name, target=target_str, expected=expected,
            route=route, method=method, resolved_ip=ip,
            rtt_ms=round(p_rtt, 1) if p_rtt is not None else None,
            direct_rtt_ms=round(d_rtt, 1) if d_rtt is not None else None,
            cn_db_match=in_cn, preference_note=pref, error=err,
        )
    else:
        samples: List[float] = []
        last_err = ""
        for _ in range(3):
            ok_i, rtt_i, err_i = tcp_tls_probe_direct(ip, port, timeout=4.0, sni=sni, proto=proto)
            if ok_i and rtt_i is not None:
                samples.append(rtt_i)
            else:
                last_err = err_i
                if not samples:
                    ok_2, rtt_2, err_2 = tcp_tls_probe_direct(ip, port, timeout=3.5, sni=sni, proto=proto)
                    if ok_2 and rtt_2 is not None:
                        samples.append(rtt_2)
                    else:
                        last_err = err_2
                    break

        ok = len(samples) > 0
        err = "" if ok else last_err
        rtt = None
        if ok:
            samples_sorted = sorted(samples)
            rtt = samples_sorted[len(samples_sorted) // 2]
            sample_str = "/".join(f"{x:.0f}" for x in samples) + "ms"
            if expected == "PROXY":
                if ip.startswith(("149.154.", "91.108.", "8.8.", "157.240.")):
                    route, method = "PROXY", f"受限纯IP可达 [{sample_str}]"
                elif rtt >= 180:
                    route, method = "PROXY", f"海外纯IP经代理 [{sample_str}]"
                else:
                    route, method = "SUSPECT_DIRECT", f"低延迟可达 [{sample_str}] (可能直连)"
            else:
                if rtt < 140:
                    route, method = "DIRECT", f"国内纯IP直连 [{sample_str}]"
                else:
                    route, method = "SUSPECT_PROXY", f"国内纯IP持续高延迟 [{sample_str}] (疑似绕路)"
        else:
            route, method = "FAILED", "连接超时/重置"
        return TestResult(
            category=category, name=name, target=target_str, expected=expected,
            route=route, method=method, resolved_ip=ip,
            rtt_ms=round(rtt, 1) if rtt is not None else None,
            cn_db_match=in_cn, preference_note=pref, error=err if not ok else "",
        )


def classify_exit_ips(
    results: List[TestResult], direct_baseline_ips: Set[str],
    cn_db: CIDRDatabase, ip_geo_cache: Dict[str, str],
) -> Tuple[Set[str], Set[str]]:
    direct_ips = set(direct_baseline_ips)
    proxy_ips: Set[str] = set()

    for r in results:
        if not r.exit_ip:
            continue
        in_cn = cn_db.contains(r.exit_ip)
        r.cn_db_match = in_cn
        if r.exit_ip in direct_ips:
            continue
        if in_cn is True:
            direct_ips.add(r.exit_ip)
        elif in_cn is False:
            proxy_ips.add(r.exit_ip)
        else:
            if r.category == "国内 IP 回显" and any(
                k in r.location for k in ("中国", "CN", "电信", "联通", "移动", "北京", "上海", "广东", "浙江", "江苏", "四川")
            ):
                direct_ips.add(r.exit_ip)

    if not direct_ips:
        cn_counts: Dict[str, int] = {}
        for r in results:
            if r.category == "国内 IP 回显" and r.exit_ip:
                cn_counts[r.exit_ip] = cn_counts.get(r.exit_ip, 0) + 1
        if cn_counts:
            top_ip = max(cn_counts, key=cn_counts.get)
            loc_str = ip_geo_cache.get(top_ip, "")
            if not loc_str or "CN" in loc_str or "中国" in loc_str:
                direct_ips.add(top_ip)

    for r in results:
        if not r.exit_ip:
            continue
        if r.exit_ip in direct_ips:
            r.route = "DIRECT"
        else:
            r.route = "PROXY"
            proxy_ips.add(r.exit_ip)
        if not r.location and r.exit_ip in ip_geo_cache:
            r.location = ip_geo_cache[r.exit_ip]

    for r in results:
        if r.route in ("FAILED", "UNKNOWN"):
            r.match_expected = False
        elif r.expected == "DIRECT":
            r.match_expected = r.route in ("DIRECT", "SUSPECT_DIRECT")
        elif r.expected == "PROXY":
            r.match_expected = r.route in ("PROXY", "SUSPECT_PROXY")

    return direct_ips, proxy_ips


def enrich_ip_locations(ips: Set[str], proxy_url: Optional[str]) -> Dict[str, str]:
    cache: Dict[str, str] = {}
    unique_ips = [ip for ip in sorted(ips) if is_valid_ip(ip) and not is_private_ip(ip)][:12]

    def query_one(ip: str) -> Tuple[str, str]:
        status, body, _, _ = http_get(
            f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,countryCode,country,regionName,city,isp,org",
            proxy_url=proxy_url,
            timeout=4.0,
        )
        if status == 200 and body:
            try:
                d = json.loads(body.decode("utf-8", errors="ignore"))
                if d.get("status") == "success":
                    loc = " ".join(
                        filter(None, [d.get("countryCode"), d.get("country"), d.get("city"), d.get("isp") or d.get("org")])
                    )
                    return ip, loc
            except Exception:
                pass
        return ip, ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        for ip, loc in ex.map(query_one, unique_ips):
            if loc:
                cache[ip] = loc
    return cache


# ==============================================================================
# Scoring & Diagnosis Engine (打分与智能修改建议引擎)
# ==============================================================================

def evaluate_audit(
    results: List[TestResult],
    direct_ips: Set[str],
    proxy_ips: Set[str],
    ip_geo_cache: Dict[str, str],
    audit_mode: str = "whitelist",
) -> AuditReport:
    diagnosis: List[DiagnosisItem] = []

    # Partition results
    cn_echo = [r for r in results if r.category == "国内 IP 回显"]
    cn_dom = [r for r in results if r.category == "国内主流网站"]
    gl_echo = [r for r in results if r.category == "海外 IP 回显"]
    gl_dom = [r for r in results if r.category == "海外主流服务" and not r.preference_note]
    ai_trace = [r for r in results if r.category == "AI/热门服务出口"]
    ai_core = [r for r in results if r.name in AI_CORE_NAMES]
    pure_cn = [r for r in results if r.category == "纯IP-国内及易误判段"]
    pure_ap = [r for r in results if r.category == "纯IP-港澳台/亚太" and not r.preference_note]
    pure_gl = [r for r in results if r.category == "纯IP-海外主流ASN"]
    pref_items = [r for r in results if r.preference_note]

    # 1. 国内直连准确度 (25 分)
    cn_all = cn_echo + cn_dom
    cn_direct_ok = [r for r in cn_all if r.route == "DIRECT"]
    cn_proxied = [r for r in cn_all if r.route in ("PROXY", "SUSPECT_PROXY")]
    cn_echo_ok = sum(1 for r in cn_echo if r.route == "DIRECT")
    cn_dom_ok = sum(1 for r in cn_dom if r.route == "DIRECT")
    score_cn = round(25 * len(cn_direct_ok) / max(len(cn_all), 1))
    dim_cn = DimensionScore(
        key="cn_direct", name="国内直连准确度", score=score_cn, max_score=25,
        summary=f"{cn_echo_ok}/{len(cn_echo)} 回显直连, {cn_dom_ok}/{len(cn_dom)} 国内站直连",
    )

    # 2. 海外代理覆盖率 (25 分)
    gl_all = gl_echo + gl_dom
    if audit_mode == "blacklist":
        # In blacklist mode, non-blocked foreign echo going direct is tolerated; blocked services must proxy
        gl_ok = [
            r for r in gl_all
            if r.route == "PROXY" or (r.category == "海外 IP 回显" and r.route == "DIRECT")
        ]
    else:
        gl_ok = [r for r in gl_all if r.route in ("PROXY", "SUSPECT_PROXY")]
    gl_echo_ok = sum(1 for r in gl_echo if r.route == "PROXY")
    gl_dom_ok = sum(1 for r in gl_dom if r.route in ("PROXY", "SUSPECT_PROXY"))
    score_gl = round(25 * len(gl_ok) / max(len(gl_all), 1))
    dim_gl = DimensionScore(
        key="global_proxy", name="海外代理覆盖率", score=score_gl, max_score=25,
        summary=f"{gl_echo_ok}/{len(gl_echo)} 海外回显走代理, {gl_dom_ok}/{len(gl_dom)} 海外站可达",
    )

    # 3. 纯 IP / GeoIP 库精准度 (20 分)
    pure_all = pure_cn + pure_ap + pure_gl
    if audit_mode == "blacklist":
        pure_ok = [
            r for r in pure_all
            if (r.expected == "DIRECT" and r.route == "DIRECT")
            or (r.expected == "PROXY" and r.route in ("PROXY", "SUSPECT_PROXY"))
            or (r.category == "纯IP-港澳台/亚太" and r.route in ("DIRECT", "SUSPECT_DIRECT"))
        ]
    else:
        pure_ok = [r for r in pure_all if r.match_expected]
    pure_cn_detour = [r for r in pure_cn if r.route == "SUSPECT_PROXY"]
    pure_gl_fail = [r for r in (pure_ap + pure_gl) if not r.match_expected]
    score_pure = round(20 * len(pure_ok) / max(len(pure_all), 1))
    pure_notes = []
    if pure_cn_detour:
        pure_notes.append(f"{len(pure_cn_detour)}项国内段疑似绕路")
    if pure_gl_fail:
        pure_notes.append(f"{len(pure_gl_fail)}项海外纯IP异常")
    if not pure_notes:
        pure_notes.append("国内易误判段与港台日/TG全通")
    dim_pure = DimensionScore(
        key="pure_ip", name="纯IP/GeoIP精准度", score=score_pure, max_score=20,
        summary=", ".join(pure_notes),
    )

    # 4. AI 与关键服务体验 (15 分)
    ai_ok = [r for r in ai_core if r.route in ("PROXY", "SUSPECT_PROXY")]
    ai_trace_core = [r for r in ai_trace if r.name in AI_CORE_NAMES and r.exit_ip]
    general_trace = [r for r in (gl_echo + [x for x in ai_trace if x.name not in AI_CORE_NAMES]) if r.exit_ip and r.route == "PROXY"]
    ai_exit_set = {r.exit_ip for r in ai_trace_core if r.route == "PROXY"}
    gen_exit_set = {r.exit_ip for r in general_trace}
    ai_isolated = bool(ai_exit_set and gen_exit_set and ai_exit_set.isdisjoint(gen_exit_set))

    ai_restricted_hits = []
    for r in ai_trace_core:
        loc_upper = (r.location or ip_geo_cache.get(r.exit_ip, "")).upper()
        tokens = set(re.findall(r"\b[A-Z]{2}\b", loc_upper))
        if tokens & set(AI_RESTRICTED_REGIONS) or "香港" in loc_upper or "中国" in loc_upper:
            ai_restricted_hits.append((r.name, r.exit_ip, r.location or ip_geo_cache.get(r.exit_ip, "")))

    score_ai = round(15 * len(ai_ok) / max(len(ai_core), 1))
    if ai_restricted_hits:
        score_ai = max(0, score_ai - 5)
    ai_summary = f"{len(ai_ok)}/{len(ai_core)} 核心AI可达"
    if ai_isolated:
        ai_summary += " · 🌟 已识别AI独立策略组"
    elif ai_restricted_hits:
        ai_summary += " · ⚠️ AI出口位于受限地区"
    dim_ai = DimensionScore(
        key="ai_service", name="AI 服务与隔离", score=score_ai, max_score=15,
        summary=ai_summary,
    )

    # 5. 路由稳定性与卫生 (15 分)
    failed_items = [r for r in results if r.route == "FAILED"]
    real_anomalies = [r for r in results if not r.match_expected and not r.preference_note]
    score_stab = 15
    score_stab -= min(10, len(failed_items) * 2)
    score_stab -= min(5, max(0, len(real_anomalies) - len(failed_items)))
    score_stab = max(0, score_stab)
    stab_summary = (
        "全量探测稳定，无超时失败"
        if not failed_items
        else f"有 {len(failed_items)} 项超时/失败"
    )
    dim_stab = DimensionScore(
        key="stability", name="路由稳定性", score=score_stab, max_score=15,
        summary=stab_summary,
    )

    dimensions = [dim_cn, dim_gl, dim_pure, dim_ai, dim_stab]
    total_score = sum(d.score for d in dimensions)

    # Grade determination
    if total_score >= 90:
        grade, emoji, tagline = "优秀", "🏆", "分流精准，国内直连不绕路，海外与 AI 稳定走代理"
    elif total_score >= 75:
        grade, emoji, tagline = "良好", "✅", "核心分流正常，存在少量边缘段或细节可按需微调"
    elif total_score >= 60:
        grade, emoji, tagline = "需要修改", "⚠️", "存在国内绕路、漏代理或 GeoIP 库偏旧，建议按下方指引修改"
    else:
        grade, emoji, tagline = "分流异常", "🚨", "代理未生效、误开全局模式或大面积规则失效，请优先排查"

    # Build actionable diagnosis items
    # Global proxy mistake?
    if len(cn_proxied) >= max(4, len(cn_all) // 2):
        diagnosis.append(
            DiagnosisItem(
                level="error",
                title=f"疑似误开「全局代理 (Global)」模式（{len(cn_proxied)}/{len(cn_all)} 个国内目标走代理）",
                detail="国内回显或国内主流网站大量返回海外代理 IP，访问国内网站会明显变慢并浪费流量。",
                suggestion="将代理客户端从 Global 切换为 Rule（规则模式），确保国内直连规则位于 MATCH 兜底之前：",
                rule_snippet=[
                    "- GEOSITE,cn,DIRECT",
                    "- GEOIP,CN,DIRECT,no-resolve",
                    "- MATCH,PROXY",
                ],
            )
        )
    elif len(cn_direct_ok) == len(cn_all):
        diagnosis.append(
            DiagnosisItem(
                level="good",
                title="国内直连 100% 精准（8/8 回显 + 10/10 主流国内站全部直连）",
                detail="未发生国内流量绕路，所有国内网站均解析为真实国内 IP 并低延迟直连。",
            )
        )

    # Proxy not working at all?
    if not proxy_ips and gl_dom_ok < len(gl_dom) // 2:
        diagnosis.append(
            DiagnosisItem(
                level="error",
                title="未检测到代理出口生效（当前可能处于纯直连状态）",
                detail="海外回显全部返回国内 IP 或连接失败，受限服务大面积不可达。",
                suggestion="请检查：1) 代理客户端是否已开启系统代理或 TUN 模式；2) 节点本身是否可用；3) 规则末尾是否为 MATCH,PROXY。",
            )
        )
    elif gl_echo_ok == len(gl_echo) and gl_dom_ok == len(gl_dom):
        diagnosis.append(
            DiagnosisItem(
                level="good",
                title=f"海外代理与兜底规则生效彻底（{gl_echo_ok}/{len(gl_echo)} 回显 + {gl_dom_ok}/{len(gl_dom)} 海外站全部走代理）",
                detail="白名单兜底 (MATCH,PROXY) 工作严格，无海外网站漏代理情况。",
            )
        )
    elif len(gl_ok) < len(gl_all):
        leaked = [r.name for r in gl_all if r not in gl_ok][:8]
        diagnosis.append(
            DiagnosisItem(
                level="warn",
                title=f"部分海外目标未走代理或不可达（{len(gl_all) - len(gl_ok)} 项）",
                detail=f"涉及目标：{', '.join(leaked)}",
                suggestion="建议检查代理模式是否为白名单兜底（规则末尾设为 MATCH,PROXY），并确认节点延迟与稳定性。",
                rule_snippet=["- MATCH,PROXY"],
            )
        )

    # AI isolation & restricted region check
    if ai_restricted_hits:
        names = ", ".join(x[0] for x in ai_restricted_hits)
        sample_loc = ai_restricted_hits[0][2]
        diagnosis.append(
            DiagnosisItem(
                level="error",
                title=f"AI 服务命中受限地区出口（{names}）",
                detail=f"检测到出口归属地为「{sample_loc}」，OpenAI / Claude / Gemini 对香港、大陆等地区严格封禁。",
                suggestion="请为 AI 服务创建独立策略组，指定美国 / 日本 / 新加坡 / 台湾等非香港纯净节点：",
                rule_snippet=[
                    "- DOMAIN-SUFFIX,openai.com,AI-Proxy",
                    "- DOMAIN-SUFFIX,chatgpt.com,AI-Proxy",
                    "- DOMAIN-SUFFIX,anthropic.com,AI-Proxy",
                    "- DOMAIN-SUFFIX,claude.ai,AI-Proxy",
                    "- DOMAIN-SUFFIX,perplexity.ai,AI-Proxy",
                ],
            )
        )
    elif ai_isolated:
        diagnosis.append(
            DiagnosisItem(
                level="good",
                title="AI 专属策略组已独立分流生效 🌟",
                detail=f"ChatGPT / OpenAI / Claude / Perplexity 走独立出口 ({', '.join(sorted(ai_exit_set))})，与常规海外代理 ({', '.join(sorted(gen_exit_set))}) 完全隔离，防风控效果极佳。",
            )
        )
    elif len(ai_ok) == len(ai_core):
        diagnosis.append(
            DiagnosisItem(
                level="good",
                title="核心 AI 服务（ChatGPT / OpenAI / Claude / Perplexity / Gemini）全部可用",
                detail="所有 AI 端点均成功通过非受限海外节点访问。",
            )
        )

    # Domestic pure IP detours (e.g. 1.12.12.12, 101.6.15.130, 101.198.198.198)
    for r in pure_cn_detour:
        ip_only = r.resolved_ip
        rules = []
        if ip_only.startswith("101.6."):
            rules = ["- DOMAIN-SUFFIX,edu.cn,DIRECT", "- IP-CIDR,101.6.0.0/16,DIRECT,no-resolve"]
            extra_tip = "如平时使用国内高校镜像站（清华/中科大），建议补入直连；若不常用，白名单模式下可忽略。"
        elif ip_only.startswith("1.12."):
            rules = ["- IP-CIDR,1.12.0.0/14,DIRECT,no-resolve"]
            extra_tip = "1.12.0.0/14 为腾讯云国内段，老旧 MaxMind GeoIP 库常误判为海外，建议更换为 gaoyifan/china-operator-ip 或 Loyalsoldier/geoip。"
        else:
            prefix = ".".join(ip_only.split(".")[:2]) + ".0.0/16"
            rules = [f"- IP-CIDR,{prefix},DIRECT,no-resolve"]
            extra_tip = "建议更新代理内核的 GeoIP 数据库至最新版 MetaCubeX/meta-rules-dat 或 Loyalsoldier/geoip。"
        diagnosis.append(
            DiagnosisItem(
                level="warn",
                title=f"[国内纯IP疑似绕路] {r.name} ({r.target}) 中位延迟 {r.rtt_ms:.0f}ms",
                detail=f"3 次采样结果：{r.method}，延迟特征接近海外代理节点。",
                suggestion=extra_tip,
                rule_snippet=rules,
            )
        )

    if not pure_cn_detour and sum(1 for r in pure_cn if r.route == "DIRECT") >= len(pure_cn) - 1:
        diagnosis.append(
            DiagnosisItem(
                level="good",
                title="国内易误判纯 IP 段（1.12.12.12 / 101.198.198.198 等）精准直连",
                detail="说明你的 GeoIP / IP-CIDR 底库非常新，没有出现老旧 MaxMind 库的国内段误判问题。",
            )
        )

    # Telegram / Overseas pure IP failures
    tg_fails = [r for r in pure_gl if "Telegram" in r.name and not r.match_expected]
    if tg_fails:
        diagnosis.append(
            DiagnosisItem(
                level="warn",
                title=f"Telegram 纯 IP 机房连通异常（{len(tg_fails)}/5 个 DC 失败）",
                detail="Telegram 客户端直接通过纯 IP 通信，不走域名规则；若缺少 Telegram IP-CIDR 规则会导致客户端转圈无法收发消息。",
                suggestion="请在规则中补充 Telegram 专属 IP-CIDR / GeoIP 规则：",
                rule_snippet=[
                    "- GEOIP,TELEGRAM,PROXY,no-resolve",
                    "- IP-CIDR,91.108.0.0/16,PROXY,no-resolve",
                    "- IP-CIDR,149.154.160.0/20,PROXY,no-resolve",
                ],
            )
        )

    # Preference hints (non-penalized info)
    for r in pref_items:
        if r.name == "Apple Global" and r.route in ("DIRECT", "SUSPECT_DIRECT"):
            diagnosis.append(
                DiagnosisItem(
                    level="info",
                    title=f"Apple Global (www.apple.com) 当前走直连/国内 CDN ({r.rtt_ms:.0f}ms)",
                    detail="绝大多数规则集默认将 Apple 放行直连以提升 iCloud / App Store 下载速度（本项不扣分）。",
                    suggestion="若你希望严格白名单（仅 apple.com.cn 直连，Apple 国际站全走代理），移除规则里的 Apple 直连组即可；否则保持现状最优。",
                )
            )
        elif "香港百度边缘" in r.name and r.route in ("DIRECT", "SUSPECT_DIRECT"):
            diagnosis.append(
                DiagnosisItem(
                    level="info",
                    title=f"香港百度边缘 IP (103.235.46.40) 当前走直连 ({r.rtt_ms:.0f}ms)",
                    detail="该 IP 携带了 www.baidu.com SNI，说明代理内核启用了域名嗅探 (Sniffing) 并命中百度直连，或将其归为百度国内段（本项不扣分）。",
                )
            )

    return AuditReport(
        total_score=total_score,
        grade=grade,
        grade_emoji=emoji,
        grade_tagline=tagline,
        audit_mode=audit_mode,
        dimensions=dimensions,
        diagnosis=diagnosis,
        ai_isolated=ai_isolated,
        ai_exit_ips=sorted(ai_exit_set),
        general_exit_ips=sorted(gen_exit_set),
    )


def route_label(route: str) -> str:
    return {
        "PROXY": "✈️ 走代理",
        "DIRECT": "🏠 直连",
        "SUSPECT_PROXY": "⚠️ 疑似走代理",
        "SUSPECT_DIRECT": "⚠️ 疑似直连",
        "FAILED": "❌ 失败/超时",
        "UNKNOWN": "❓ 未知",
    }.get(route, route)


def progress_bar(score: int, max_score: int, width: int = 20) -> str:
    ratio = max(0.0, min(1.0, score / max(max_score, 1)))
    filled = round(ratio * width)
    bar = "█" * filled + "░" * (width - filled)
    if ratio >= 0.9:
        return Color.green(bar)
    elif ratio >= 0.7:
        return Color.yellow(bar)
    return Color.red(bar)


def print_terminal_report(
    proxy_env: ProxyEnv,
    cn_db: CIDRDatabase,
    direct_ips: Set[str],
    proxy_ips: Set[str],
    ip_geo_cache: Dict[str, str],
    results: List[TestResult],
    audit: AuditReport,
    show_detail: bool = False,
    html_path: Optional[str] = None,
    json_path: Optional[str] = None,
):
    mode_cn = "白名单模式 · 确定国内直连/其余走代理" if audit.audit_mode == "whitelist" else "黑名单模式 · 受限走代理/其余直连"
    score_color = (
        Color.green if audit.total_score >= 90
        else Color.cyan if audit.total_score >= 75
        else Color.yellow if audit.total_score >= 60
        else Color.red
    )

    print()
    print(Color.bold("=" * 84))
    print(Color.bold(f"  🧭 IP Split Audit v{VERSION} · 代理分流一键体检报告 ({mode_cn})"))
    print(Color.bold("=" * 84))
    print(
        f"  综合评分 :  {score_color(Color.bold(f'{audit.total_score} / 100'))}  │  "
        f"评级: {score_color(Color.bold(f'{audit.grade_emoji} {audit.grade}'))}  ({audit.grade_tagline})"
    )
    print(f"  测试时间 :  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  网络环境 :  {proxy_env.mode_summary}")
    if cn_db.count:
        print(f"  校验库   :  {cn_db.name} ({cn_db.count} 条中国 IPv4 CIDR)")
    else:
        print("  校验库   :  未能在线同步 (已使用多源回显与延迟对比判定)")

    print(Color.bold("\n  [分项体检]"))
    for d in audit.dimensions:
        bar = progress_bar(d.score, d.max_score)
        print(f"  {d.name:<14} {bar}  {d.score:>2} / {d.max_score:<2}  {Color.dim('(' + d.summary + ')')}")

    print(Color.bold("\n  [出口线路识别]"))
    if direct_ips:
        for ip in sorted(direct_ips):
            loc = ip_geo_cache.get(ip, "中国大陆直连")
            print(f"  🏠 国内直连      : {Color.green(ip):<26} ({loc})")
    else:
        print(f"  🏠 国内直连      : {Color.yellow('未检测到国内直连出口')}")

    if proxy_ips:
        for ip in sorted(proxy_ips):
            loc = ip_geo_cache.get(ip, "海外代理")
            matched = [r.name for r in results if r.exit_ip == ip]
            if ip in audit.ai_exit_ips and ip not in audit.general_exit_ips:
                tag = Color.magenta("🤖 AI 专属代理   ")
            elif audit.ai_isolated and ip in audit.general_exit_ips:
                tag = Color.cyan("✈️ 普通海外代理  ")
            else:
                tag = Color.cyan("✈️ 代理出口      ")
            preview = ", ".join(matched[:6]) + (f" 等 {len(matched)} 项" if len(matched) > 6 else "")
            print(f"  {tag}: {Color.cyan(ip):<26} ({loc})")
            if preview:
                print(f"                     {Color.dim('命中: ' + preview)}")
    else:
        print(f"  ✈️ 代理出口      : {Color.red('未检测到代理出口')}")

    # Diagnosis & actionable fix directions
    print("\n" + "-" * 84)
    print(Color.bold("  🩺 诊断结论与修改方向"))
    print("-" * 84)

    goods = [x for x in audit.diagnosis if x.level == "good"]
    issues = [x for x in audit.diagnosis if x.level in ("error", "warn")]
    infos = [x for x in audit.diagnosis if x.level == "info"]

    if goods:
        print(Color.green("  ✅ 表现优秀的方面:"))
        for item in goods:
            print(f"     • {Color.bold(item.title)}")
            print(f"       {Color.dim(item.detail)}")

    if issues:
        print(Color.yellow(f"\n  ⚠️ 建议修改 / 排查项 ({len(issues)} 项):"))
        for idx, item in enumerate(issues, 1):
            badge = Color.red("[严重]") if item.level == "error" else Color.yellow("[建议]")
            print(f"     {idx}. {badge} {Color.bold(item.title)}")
            print(f"        原因: {item.detail}")
            if item.suggestion:
                print(f"        修改方向: {Color.cyan(item.suggestion)}")
            if item.rule_snippet:
                for line in item.rule_snippet:
                    print(f"          {Color.green(line)}")
    else:
        print(Color.green("\n  🎉 未发现需要修改的分流异常！"))

    if infos:
        print(Color.cyan(f"\n  ℹ️ 偏好提示 (不扣分):"))
        for item in infos:
            print(f"     • {item.title}")
            if item.suggestion:
                print(f"       {Color.dim(item.suggestion)}")

    # Category summary
    print("\n" + "-" * 84)
    print(Color.bold("  📊 分类分流汇总"))
    print("-" * 84)
    cats: List[str] = []
    for r in results:
        if r.category not in cats:
            cats.append(r.category)
    for cat in cats:
        cr = [r for r in results if r.category == cat]
        n_proxy = sum(1 for r in cr if r.route in ("PROXY", "SUSPECT_PROXY"))
        n_direct = sum(1 for r in cr if r.route in ("DIRECT", "SUSPECT_DIRECT"))
        n_fail = sum(1 for r in cr if r.route == "FAILED")
        n_warn = sum(1 for r in cr if not r.match_expected and not r.preference_note)
        status_txt = Color.green("✓ 正常") if n_warn == 0 else Color.yellow(f"! {n_warn}项关注")
        print(
            f"  [{cat:<12}] 共{len(cr):>2}项 │ "
            f"✈️ 代理:{n_proxy:>2}  🏠 直连:{n_direct:>2}  ❌ 失败:{n_fail:>2} │ {status_txt}"
        )

    # Optional full detail table
    if show_detail:
        print("\n" + "=" * 84)
        print(Color.bold(f"  📋 全部 {len(results)} 项详细测试明细"))
        print("=" * 84)
        for cat in cats:
            cr = [r for r in results if r.category == cat]
            print(f"\n【{cat}】 ({len(cr)} 项)")
            print(f"{'测试项':<24} {'分流结果':<12} {'预期':<4} {'延迟':<8} {'出口IP/解析IP':<17} {'说明'}")
            print("-" * 84)
            for r in cr:
                rtt_s = f"{r.rtt_ms:.0f}ms" if r.rtt_ms is not None else "-"
                ip_s = r.exit_ip or r.resolved_ip or "-"
                exp_s = "直连" if r.expected == "DIRECT" else "代理"
                flag = "" if (r.match_expected or r.preference_note) else " [!]"
                parts = []
                if r.location:
                    parts.append(r.location)
                if r.colo:
                    parts.append(f"CF:{r.colo}")
                parts.append(r.method)
                if r.error:
                    parts.append(f"Err:{r.error[:32]}")
                print(f"{r.name:<22} {route_label(r.route) + flag:<12} {exp_s:<4} {rtt_s:<8} {ip_s:<17} {' | '.join(parts)}")

    print("\n" + "=" * 84)
    if html_path:
        print(f"  🌐 可视化网页报告 : {html_path}")
    if json_path:
        print(f"  📄 JSON 原始数据  : {json_path}")
    if not show_detail:
        print(Color.dim("  提示: 加 --detail 可在窗口打印全部 86 项明细 │ 加 --open 自动打开网页版报告"))
    print("=" * 84)


# ==============================================================================
# Self-Contained Offline HTML Report Generator
# ==============================================================================

def generate_html_report(
    proxy_env: ProxyEnv,
    cn_db: CIDRDatabase,
    direct_ips: Set[str],
    proxy_ips: Set[str],
    ip_geo_cache: Dict[str, str],
    results: List[TestResult],
    audit: AuditReport,
    out_path: Path,
):
    e = html.escape
    score_color = (
        "#22c55e" if audit.total_score >= 90
        else "#38bdf8" if audit.total_score >= 75
        else "#f59e0b" if audit.total_score >= 60
        else "#ef4444"
    )
    mode_label = "白名单模式（确定国内直连 / 不确定走代理）" if audit.audit_mode == "whitelist" else "黑名单模式（受限走代理 / 其余直连）"

    # Dimension bars HTML
    dims_html = []
    for d in audit.dimensions:
        pct = round(100 * d.score / max(d.max_score, 1))
        bar_c = "#22c55e" if pct >= 90 else "#f59e0b" if pct >= 70 else "#ef4444"
        dims_html.append(
            f"""
            <div class="dim-row">
              <div class="dim-head">
                <span class="dim-name">{e(d.name)}</span>
                <span class="dim-score">{d.score} / {d.max_score}</span>
              </div>
              <div class="bar-bg"><div class="bar-fg" style="width:{pct}%;background:{bar_c}"></div></div>
              <div class="dim-sub">{e(d.summary)}</div>
            </div>
            """
        )

    # Exit cards HTML
    exit_cards = []
    for ip in sorted(direct_ips):
        loc = ip_geo_cache.get(ip, "中国大陆直连")
        exit_cards.append(
            f'<div class="exit-card direct"><div class="exit-tag">🏠 国内直连出口</div>'
            f'<div class="exit-ip">{e(ip)}</div><div class="exit-loc">{e(loc)}</div></div>'
        )
    for ip in sorted(proxy_ips):
        loc = ip_geo_cache.get(ip, "海外代理")
        matched = [r.name for r in results if r.exit_ip == ip]
        is_ai = ip in audit.ai_exit_ips and ip not in audit.general_exit_ips
        cls = "ai" if is_ai else "proxy"
        tag = "🤖 AI 专属代理出口" if is_ai else ("✈️ 普通海外代理出口" if audit.ai_isolated else "✈️ 代理出口")
        m_str = "、".join(matched[:8]) + (f" 等 {len(matched)} 项" if len(matched) > 8 else "")
        exit_cards.append(
            f'<div class="exit-card {cls}"><div class="exit-tag">{tag}</div>'
            f'<div class="exit-ip">{e(ip)}</div><div class="exit-loc">{e(loc)}</div>'
            f'<div class="exit-hits">命中: {e(m_str)}</div></div>'
        )
    if not exit_cards:
        exit_cards.append('<div class="exit-card warn"><div class="exit-tag">⚠️ 未检测到出口 IP</div></div>')

    # Diagnosis HTML
    diag_html = []
    icon_map = {"good": "✅", "warn": "⚠️", "error": "🚨", "info": "ℹ️"}
    for idx, item in enumerate(audit.diagnosis):
        snippet_block = ""
        if item.rule_snippet:
            code_txt = "\n".join(item.rule_snippet)
            snippet_block = (
                f'<div class="code-wrap"><pre id="rule-{idx}">{e(code_txt)}</pre>'
                f'<button class="copy-btn" onclick="copyRule(\'rule-{idx}\', this)">复制规则</button></div>'
            )
        sugg_block = f'<div class="diag-sugg">👉 修改方向：{e(item.suggestion)}</div>' if item.suggestion else ""
        diag_html.append(
            f"""
            <div class="diag-card {e(item.level)}">
              <div class="diag-title">{icon_map.get(item.level, '•')} {e(item.title)}</div>
              <div class="diag-detail">{e(item.detail)}</div>
              {sugg_block}
              {snippet_block}
            </div>
            """
        )

    # Rows HTML
    rows_html = []
    for r in results:
        if r.route in ("PROXY", "SUSPECT_PROXY"):
            r_group = "proxy"
            badge_cls = "badge-proxy" if r.route == "PROXY" else "badge-warn"
        elif r.route in ("DIRECT", "SUSPECT_DIRECT"):
            r_group = "direct"
            badge_cls = "badge-direct" if r.route == "DIRECT" else "badge-warn"
        else:
            r_group = "failed"
            badge_cls = "badge-fail"
        is_anom = "1" if (not r.match_expected and not r.preference_note) else "0"
        rtt_s = f"{r.rtt_ms:.0f} ms" if r.rtt_ms is not None else "-"
        ip_s = r.exit_ip or r.resolved_ip or "-"
        exp_s = "直连" if r.expected == "DIRECT" else "代理"
        details = []
        if r.location:
            details.append(r.location)
        if r.colo:
            details.append(f"CF:{r.colo}")
        details.append(r.method)
        if r.error:
            details.append(f"Err: {r.error}")
        rows_html.append(
            f'<tr data-route="{r_group}" data-anom="{is_anom}">'
            f'<td><span class="cat-pill">{e(r.category)}</span></td>'
            f'<td class="name-col">{e(r.name)}<div class="target-sub">{e(r.target)}</div></td>'
            f'<td><span class="badge {badge_cls}">{e(route_label(r.route))}</span></td>'
            f'<td>{exp_s}</td>'
            f'<td class="mono">{e(rtt_s)}</td>'
            f'<td class="mono">{e(ip_s)}</td>'
            f'<td class="detail-col">{e(" | ".join(details))}</td>'
            f'</tr>'
        )

    total = len(results)
    n_proxy = sum(1 for r in results if r.route in ("PROXY", "SUSPECT_PROXY"))
    n_direct = sum(1 for r in results if r.route in ("DIRECT", "SUSPECT_DIRECT"))
    n_anom = sum(1 for r in results if not r.match_expected and not r.preference_note)
    n_fail = sum(1 for r in results if r.route == "FAILED")

    doc = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>IP Split Audit · 代理分流体检报告 ({audit.total_score}分 · {e(audit.grade)})</title>
<style>
  :root {{
    --bg: #0b1120; --card: #111827; --border: #1f2937; --text: #e5e7eb; --muted: #9ca3af;
    --green: #22c55e; --blue: #38bdf8; --purple: #c084fc; --yellow: #f59e0b; --red: #ef4444;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 24px; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    line-height: 1.55;
  }}
  .container {{ max-width: 1180px; margin: 0 auto; }}
  .hero {{
    display: grid; grid-template-columns: 240px 1fr; gap: 24px;
    background: linear-gradient(135deg, #111827 0%, #162033 100%);
    border: 1px solid var(--border); border-radius: 16px; padding: 24px; margin-bottom: 20px;
  }}
  .score-box {{
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    background: rgba(15,23,42,.7); border: 1px solid var(--border); border-radius: 14px; padding: 20px;
    text-align: center;
  }}
  .score-num {{ font-size: 56px; font-weight: 800; color: {score_color}; line-height: 1.05; }}
  .score-den {{ font-size: 15px; color: var(--muted); }}
  .grade-pill {{
    margin-top: 10px; padding: 4px 14px; border-radius: 999px; font-weight: 700; font-size: 15px;
    background: rgba(255,255,255,.07); color: {score_color}; border: 1px solid {score_color};
  }}
  .meta h1 {{ margin: 0 0 6px; font-size: 22px; }}
  .tagline {{ color: #cbd5e1; margin-bottom: 12px; font-size: 15px; }}
  .meta-grid {{ display: flex; flex-wrap: wrap; gap: 10px 20px; font-size: 13px; color: var(--muted); margin-bottom: 16px; }}
  .dims {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }}
  .dim-row {{ background: rgba(15,23,42,.55); border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; }}
  .dim-head {{ display: flex; justify-content: space-between; font-size: 13px; font-weight: 600; margin-bottom: 6px; }}
  .bar-bg {{ height: 7px; background: #1f2937; border-radius: 99px; overflow: hidden; }}
  .bar-fg {{ height: 100%; border-radius: 99px; }}
  .dim-sub {{ font-size: 12px; color: var(--muted); margin-top: 5px; }}
  .section-title {{ font-size: 17px; font-weight: 700; margin: 22px 0 12px; display: flex; align-items: center; gap: 8px; }}
  .exit-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); gap: 14px; }}
  .exit-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px;
    border-left: 4px solid var(--blue);
  }}
  .exit-card.direct {{ border-left-color: var(--green); }}
  .exit-card.ai {{ border-left-color: var(--purple); }}
  .exit-card.warn {{ border-left-color: var(--yellow); }}
  .exit-tag {{ font-size: 12px; color: var(--muted); font-weight: 600; }}
  .exit-ip {{ font-family: Consolas, monospace; font-size: 20px; font-weight: 700; margin: 4px 0; }}
  .exit-loc {{ font-size: 13px; color: #cbd5e1; }}
  .exit-hits {{ font-size: 12px; color: var(--muted); margin-top: 6px; }}
  .diag-list {{ display: grid; gap: 10px; }}
  .diag-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px;
    border-left: 4px solid var(--blue);
  }}
  .diag-card.good {{ border-left-color: var(--green); }}
  .diag-card.warn {{ border-left-color: var(--yellow); }}
  .diag-card.error {{ border-left-color: var(--red); }}
  .diag-card.info {{ border-left-color: var(--blue); }}
  .diag-title {{ font-weight: 700; font-size: 14px; margin-bottom: 4px; }}
  .diag-detail {{ font-size: 13px; color: #cbd5e1; }}
  .diag-sugg {{ font-size: 13px; color: #7dd3fc; margin-top: 6px; }}
  .code-wrap {{ position: relative; margin-top: 8px; }}
  .code-wrap pre {{
    margin: 0; padding: 10px 12px; background: #090d16; border: 1px solid #1f2937;
    border-radius: 8px; font-family: Consolas, monospace; font-size: 12px; color: #86efac; overflow-x: auto;
  }}
  .copy-btn {{
    position: absolute; top: 6px; right: 8px; background: #1e293b; color: #e2e8f0; border: 1px solid #334155;
    border-radius: 6px; padding: 3px 10px; font-size: 12px; cursor: pointer;
  }}
  .copy-btn:hover {{ background: #334155; }}
  .toolbar {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 12px; }}
  .filter-btn {{
    background: var(--card); color: var(--text); border: 1px solid var(--border);
    padding: 6px 12px; border-radius: 8px; cursor: pointer; font-size: 13px;
  }}
  .filter-btn.active {{ background: #1d4ed8; border-color: #2563eb; color: #fff; }}
  .search-input {{
    margin-left: auto; background: var(--card); color: var(--text); border: 1px solid var(--border);
    padding: 6px 12px; border-radius: 8px; font-size: 13px; min-width: 220px;
  }}
  .table-wrap {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; overflow: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 10px 12px; background: #0f172a; color: var(--muted); font-weight: 600; white-space: nowrap; }}
  td {{ padding: 9px 12px; border-top: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: rgba(255,255,255,.025); }}
  .cat-pill {{ background: #1e293b; color: #cbd5e1; padding: 2px 8px; border-radius: 6px; font-size: 12px; white-space: nowrap; }}
  .name-col {{ font-weight: 600; }}
  .target-sub {{ font-size: 11px; color: var(--muted); font-weight: 400; font-family: Consolas, monospace; }}
  .mono {{ font-family: Consolas, monospace; white-space: nowrap; }}
  .detail-col {{ color: #cbd5e1; font-size: 12px; }}
  .badge {{ padding: 2px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; white-space: nowrap; }}
  .badge-proxy {{ background: rgba(56,189,248,.15); color: #38bdf8; }}
  .badge-direct {{ background: rgba(34,197,94,.15); color: #4ade80; }}
  .badge-warn {{ background: rgba(245,158,11,.18); color: #fbbf24; }}
  .badge-fail {{ background: rgba(239,68,68,.18); color: #f87171; }}
  footer {{ text-align: center; color: var(--muted); font-size: 12px; margin-top: 24px; }}
  @media (max-width: 760px) {{ .hero {{ grid-template-columns: 1fr; }} .search-input {{ margin-left: 0; width: 100%; }} }}
</style>
</head>
<body>
<div class="container">
  <div class="hero">
    <div class="score-box">
      <div class="score-num">{audit.total_score}</div>
      <div class="score-den">满分 100</div>
      <div class="grade-pill">{e(audit.grade_emoji)} {e(audit.grade)}</div>
    </div>
    <div class="meta">
      <h1>🧭 IP Split Audit · 代理分流体检报告</h1>
      <div class="tagline">{e(audit.grade_tagline)}</div>
      <div class="meta-grid">
        <span>模式：{e(mode_label)}</span>
        <span>环境：{e(proxy_env.mode_summary)}</span>
        <span>IP 库：{e(cn_db.name)} ({cn_db.count} CIDR)</span>
        <span>时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
      </div>
      <div class="dims">{''.join(dims_html)}</div>
    </div>
  </div>

  <div class="section-title">🌐 出口线路识别</div>
  <div class="exit-grid">{''.join(exit_cards)}</div>

  <div class="section-title">🩺 诊断结论与修改方向</div>
  <div class="diag-list">{''.join(diag_html)}</div>

  <div class="section-title">📋 全量分流测试明细 ({total} 项)</div>
  <div class="toolbar">
    <button class="filter-btn active" onclick="setFilter('all', this)">全部 ({total})</button>
    <button class="filter-btn" onclick="setFilter('proxy', this)">✈️ 走代理 ({n_proxy})</button>
    <button class="filter-btn" onclick="setFilter('direct', this)">🏠 直连 ({n_direct})</button>
    <button class="filter-btn" onclick="setFilter('anom', this)">⚠️ 异常/关注 ({n_anom})</button>
    <button class="filter-btn" onclick="setFilter('failed', this)">❌ 失败 ({n_fail})</button>
    <input class="search-input" id="searchInput" placeholder="搜索域名、IP、分类或说明..." oninput="applyFilters()" />
  </div>
  <div class="table-wrap">
    <table id="resultTable">
      <thead>
        <tr><th>分类</th><th>测试项</th><th>分流结果</th><th>预期</th><th>延迟</th><th>出口IP / 解析IP</th><th>归属地与判定依据</th></tr>
      </thead>
      <tbody>{''.join(rows_html)}</tbody>
    </table>
  </div>
  <footer>Generated by IP Split Audit v{VERSION} · 本地离线报告（不会上传任何个人 IP 数据）</footer>
</div>
<script>
let currentFilter = 'all';
function setFilter(f, btn) {{
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}}
function applyFilters() {{
  const q = document.getElementById('searchInput').value.trim().toLowerCase();
  document.querySelectorAll('#resultTable tbody tr').forEach(tr => {{
    const r = tr.dataset.route;
    const a = tr.dataset.anom;
    let show = true;
    if (currentFilter === 'proxy') show = (r === 'proxy');
    else if (currentFilter === 'direct') show = (r === 'direct');
    else if (currentFilter === 'failed') show = (r === 'failed');
    else if (currentFilter === 'anom') show = (a === '1');
    if (show && q) show = tr.innerText.toLowerCase().includes(q);
    tr.style.display = show ? '' : 'none';
  }});
}}
function copyRule(id, btn) {{
  const txt = document.getElementById(id).innerText;
  navigator.clipboard.writeText(txt).then(() => {{
    const old = btn.innerText; btn.innerText = '已复制 ✓';
    setTimeout(() => btn.innerText = old, 1500);
  }});
}}
</script>
</body>
</html>
"""
    out_path.write_text(doc, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="IP Split Audit · 零依赖代理分流一键体检工具（自动打分 + 规则修改建议 + 可视化报告）"
    )
    parser.add_argument("--mode", choices=["whitelist", "blacklist"], default="whitelist",
                        help="评分基准模式: whitelist(默认, 确定国内直连其余走代理) 或 blacklist(受限走代理其余直连)")
    parser.add_argument("--detail", action="store_true", help="在终端窗口展开打印全部 86 项明细表格")
    parser.add_argument("--open", action="store_true", help="测试完成后自动用浏览器打开可视化 HTML 报告")
    parser.add_argument("--proxy", help="手动指定本地代理地址，例如 http://127.0.0.1:7890")
    parser.add_argument("--skip-sync", action="store_true", help="跳过在线同步最新中国 IP 库")
    parser.add_argument("--check-ip", help="快速查询单个 IP 是否命中主流中国大陆 IP 库")
    parser.add_argument("--no-color", action="store_true", help="禁用终端彩色输出")
    parser.add_argument("--html-out", default=str(SCRIPT_DIR / "report.html"), help="HTML 可视化报告输出路径")
    parser.add_argument("--json-out", default=str(DATA_DIR / "last_report.json"), help="JSON 报告输出路径")
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        if args.no_color:
            Color.enabled = False

    proxy_env = detect_proxy_env(args.proxy)
    print(f"[1/4] 检测到网络环境: {proxy_env.mode_summary}")

    print("[2/4] 正在加载/同步主流开源中国 IP 库 (gaoyifan / Loyalsoldier / 17mon)...")
    cn_db = load_or_sync_cn_db(proxy_env.effective_proxy_url, skip_sync=args.skip_sync)
    if cn_db.count:
        print(f"      已加载: {cn_db.name} ({cn_db.count} 条 CIDR)")
    else:
        print("      未能在线同步，将使用多源回显与延迟对比判定")

    if args.check_ip:
        res = cn_db.contains(args.check_ip)
        label = "🇨🇳 中国大陆 IP (建议直连)" if res is True else ("🌐 非中国大陆 IP (建议走代理)" if res is False else "❓ 无法判定")
        print(f"查询结果: {args.check_ip} -> {label}")
        return

    direct_baseline_ips: Set[str] = set()
    if proxy_env.effective_proxy_url and not proxy_env.tun_adapters:
        for _, _, url, ptype, _ in ECHO_CN_TESTS[:3]:
            st, body, _, _ = http_get(url, bypass_proxy=True, timeout=3.5)
            if st == 200 and body:
                ip_val, _, _ = parse_echo_response(ptype, body)
                if ip_val and is_valid_ip(ip_val):
                    direct_baseline_ips.add(ip_val)
                    break

    total_targets = (
        len(ECHO_CN_TESTS) + len(ECHO_GLOBAL_TESTS) + len(SERVICE_TRACE_TESTS)
        + len(CN_DOMAIN_TESTS) + len(GLOBAL_DOMAIN_TESTS) + len(PURE_IP_TESTS)
    )
    print(f"[3/4] 正在并发执行 {total_targets} 项全场景分流测试（含纯 IP 3次采样）...")
    results: List[TestResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futs = []
        for cat, name, url, ptype, exp in ECHO_CN_TESTS + ECHO_GLOBAL_TESTS:
            futs.append(ex.submit(run_echo_test, cat, name, url, ptype, exp, proxy_env.effective_proxy_url, cn_db))
        for cat, name, url, exp in SERVICE_TRACE_TESTS:
            futs.append(ex.submit(run_service_trace_test, cat, name, url, exp, proxy_env.effective_proxy_url, cn_db))
        for cat, name, url, exp in CN_DOMAIN_TESTS + GLOBAL_DOMAIN_TESTS:
            futs.append(ex.submit(run_domain_test, cat, name, url, exp, proxy_env, cn_db))
        for cat, name, ip, port, exp, sni, proto in PURE_IP_TESTS:
            futs.append(ex.submit(run_pure_ip_test, cat, name, ip, port, exp, sni, proto, proxy_env, cn_db))
        for f in futs:
            results.append(f.result())

    print("[4/4] 正在汇总出口 IP、执行五维打分并生成修改建议...")
    all_exit_ips = {r.exit_ip for r in results if r.exit_ip} | direct_baseline_ips
    ip_geo_cache = enrich_ip_locations(all_exit_ips, proxy_env.effective_proxy_url)
    direct_ips, proxy_ips = classify_exit_ips(results, direct_baseline_ips, cn_db, ip_geo_cache)
    audit = evaluate_audit(results, direct_ips, proxy_ips, ip_geo_cache, audit_mode=args.mode)

    html_out_path = Path(args.html_out)
    json_out_path = Path(args.json_out)
    json_out_path.parent.mkdir(parents=True, exist_ok=True)
    generate_html_report(proxy_env, cn_db, direct_ips, proxy_ips, ip_geo_cache, results, audit, html_out_path)

    out_data = {
        "version": VERSION,
        "timestamp": datetime.now().isoformat(),
        "audit": asdict(audit),
        "proxy_env": asdict(proxy_env),
        "cn_db": {"name": cn_db.name, "count": cn_db.count},
        "direct_ips": sorted(direct_ips),
        "proxy_ips": sorted(proxy_ips),
        "ip_geo_cache": ip_geo_cache,
        "results": [asdict(r) for r in results],
    }
    json_out_path.write_text(json.dumps(out_data, ensure_ascii=False, indent=2), encoding="utf-8")

    print_terminal_report(
        proxy_env, cn_db, direct_ips, proxy_ips, ip_geo_cache, results, audit,
        show_detail=args.detail, html_path=str(html_out_path), json_path=str(json_out_path),
    )

    if args.open:
        try:
            webbrowser.open(html_out_path.resolve().as_uri())
        except Exception:
            pass


if __name__ == "__main__":
    main()
