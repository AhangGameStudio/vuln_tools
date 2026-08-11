#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aivuln CLI — Python 版漏洞扫描工具
用法:
  python vuln_cli.py scan <target> [--pocs <dir>] [--interval <sec>] [--ai]
  python vuln_cli.py /ai
  python vuln_cli.py /AI配置
  python vuln_cli.py list [--pocs <dir>]
  python vuln_cli.py help
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

# ─── 依赖检查 ───────────────────────────────────────────────
def _check_deps():
    missing = []
    try:
        import yaml
    except ImportError:
        missing.append("pyyaml")
    try:
        import requests
    except ImportError:
        missing.append("requests")
    if missing:
        print(f"[!] 缺少依赖: {', '.join(missing)}")
        print(f"    请运行: pip install {' '.join(missing)}")
        sys.exit(1)

_check_deps()

import yaml
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from urllib.parse import urljoin, urlparse

# ─── 常量 ───────────────────────────────────────────────────
POC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pocs")
CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "ai_config.json")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ─── AI 配置管理 ────────────────────────────────────────────
def load_ai_config():
    """加载 AI 配置"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"api_url": "", "api_key": "", "model": ""}

def save_ai_config(cfg):
    """保存 AI 配置"""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    print("[✓] AI 配置已保存")

def config_ai_interactive():
    """交互式配置 AI"""
    print("\n═══ AI 配置 ═══")
    cfg = load_ai_config()
    print(f"  当前 API_URL : {cfg.get('api_url', '(未设置)')}")
    print(f"  当前 API_KEY : {cfg.get('api_key', '(未设置)')[:8]}{'...' if len(cfg.get('api_key','')) > 8 else ''}")
    print(f"  当前 MODEL   : {cfg.get('model', '(未设置)')}")
    print()

    api_url = input(f"API_URL  [{cfg.get('api_url','')}]: ").strip()
    api_key = input(f"API_KEY  [{cfg.get('api_key','')[:8]}{'...' if len(cfg.get('api_key','')) > 8 else ''}]: ").strip()
    model   = input(f"MODEL    [{cfg.get('model','')}]: ").strip()

    if api_url:
        cfg["api_url"] = api_url
    if api_key:
        cfg["api_key"] = api_key
    if model:
        cfg["model"] = model

    save_ai_config(cfg)

def call_ai(prompt: str) -> str:
    """调用 AI API 进行分析"""
    cfg = load_ai_config()
    if not cfg.get("api_url") or not cfg.get("api_key"):
        return "[!] AI 未配置，请先运行 /ai 配置"

    try:
        from openai import OpenAI
        client = OpenAI(base_url=cfg["api_url"], api_key=cfg["api_key"])
        resp = client.chat.completions.create(
            model=cfg.get("model", "gpt-3.5-turbo"),
            messages=[{"role": "user", "content": prompt}],
            timeout=60,
        )
        return resp.choices[0].message.content
    except ImportError:
        # 不用 openai 库，直接用 requests
        import requests as req
        headers = {
            "Authorization": f"Bearer {cfg['api_key']}",
            "Content-Type": "application/json",
        }
        data = {
            "model": cfg.get("model", "gpt-3.5-turbo"),
            "messages": [{"role": "user", "content": prompt}],
        }
        r = req.post(f"{cfg['api_url'].rstrip('/')}/chat/completions", json=data, headers=headers, timeout=60)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"[!] AI 调用失败: {e}"

# ─── POC 解析 ───────────────────────────────────────────────
class FlexString:
    """兼容 YAML 标量字符串和字符串列表"""
    def __init__(self, val):
        if isinstance(val, list):
            self._vals = [str(v) for v in val]
        else:
            self._vals = [str(val)] if val else []

    def first(self):
        return self._vals[0] if self._vals else ""

    def all(self):
        return self._vals

class Matcher:
    """POC 匹配器"""
    def __init__(self, raw: dict):
        self.type = raw.get("type", "word")
        self.status = raw.get("status", [])
        self.words = raw.get("words", [])
        self.regex = raw.get("regex", [])
        self.part = raw.get("part", "body")
        self.condition = raw.get("condition", "and")
        self.negate = raw.get("negate", False)

    def match(self, status_code: int, body: str, headers: dict) -> bool:
        result = False
        if self.type == "status":
            result = status_code in self.status
        elif self.type == "word":
            if self.part == "header":
                header_str = " ".join(f"{k}: {v}" for k, vs in headers.items() for v in (vs if isinstance(vs, list) else [vs]))
                text = header_str
            else:
                text = body
            if self.condition == "or":
                result = any(w.lower() in text.lower() for w in self.words)
            else:
                result = all(w.lower() in text.lower() for w in self.words)
        elif self.type == "regex":
            text = body if self.part != "header" else str(headers)
            if self.condition == "or":
                result = any(re.search(p, text, re.IGNORECASE) for p in self.regex)
            else:
                result = all(re.search(p, text, re.IGNORECASE) for p in self.regex)
        elif self.type == "dsl":
            result = self._eval_dsl(status_code, body, headers)

        if self.negate:
            result = not result
        return result

    def _eval_dsl(self, status_code: int, body: str, headers: dict) -> bool:
        """简化 DSL 评估"""
        results = []
        for expr in self.regex:  # 复用 regex 字段存 dsl 表达式
            expr = expr.strip()
            # contains(body, "xxx")
            m = re.match(r'contains\((body|header),\s*"([^"]+)"\)', expr, re.IGNORECASE)
            if m:
                part, keyword = m.group(1), m.group(2)
                text = body if part == "body" else str(headers)
                results.append(keyword.lower() in text.lower())
                continue
            # status_code == N
            m = re.match(r'status_code\s*(==|!=|>=|>|<|<=)\s*(\d+)', expr, re.IGNORECASE)
            if m:
                op, n = m.group(1), int(m.group(2))
                if op == "==": results.append(status_code == n)
                elif op == "!=": results.append(status_code != n)
                elif op == ">=": results.append(status_code >= n)
                elif op == ">":  results.append(status_code > n)
                elif op == "<=": results.append(status_code <= n)
                elif op == "<":  results.append(status_code < n)
                continue
        cond = self.condition.lower()
        if cond == "or":
            return any(results) if results else False
        return all(results) if results else False

class Extractor:
    """POC 提取器"""
    def __init__(self, raw: dict):
        self.type = raw.get("type", "regex")
        self.name = raw.get("name", "")
        self.regex = raw.get("regex", [])
        self.group = raw.get("group", 0)

    def extract(self, body: str, headers: dict) -> str:
        if self.type == "regex":
            for pattern in self.regex:
                m = re.search(pattern, body)
                if m:
                    try:
                        return m.group(self.group)
                    except IndexError:
                        return m.group(0)
        elif self.type == "header":
            for k, vs in headers.items():
                if k.lower() == self.name.lower():
                    return vs[0] if isinstance(vs, list) else str(vs)
        return ""

class POC:
    """POC 定义"""
    def __init__(self, raw: dict):
        self.id = raw.get("id", "unknown")
        info = raw.get("info", {})
        self.name = info.get("name", self.id)
        self.author = info.get("author", "")
        self.severity = info.get("severity", "info")
        self.description = info.get("description", "")
        self.tags = info.get("tags", [])

        # 兼容 requests → http
        http_list = raw.get("http", raw.get("requests", []))
        self.requests = []
        for req in http_list:
            self.requests.append(POCRequest(req))

    def severity_rank(self):
        return SEVERITY_ORDER.get(self.severity.lower(), 99)

class POCRequest:
    """单个 POC 请求"""
    def __init__(self, raw: dict):
        self.method = raw.get("method", "GET").upper()
        self.path = FlexString(raw.get("path", "/"))
        self.headers = raw.get("headers", {})
        self.body = raw.get("body", "")
        self.raw = raw.get("raw", [])
        self.max_redirects = raw.get("max-redirects", 3)
        self.timeout = raw.get("timeout", 10)
        self.matchers_condition = raw.get("matchers-condition", "and")
        self.matchers = [Matcher(m) for m in raw.get("matchers", [])]
        self.extractors = [Extractor(e) for e in raw.get("extractors", [])]

def parse_raw_request(raw: str):
    """解析 nuclei 原始 HTTP 报文"""
    lines = raw.split("\n")
    req_lines = []
    timeout = 0
    for ln in lines:
        trimmed = ln.strip()
        if trimmed.startswith("@"):
            if trimmed.startswith("@timeout"):
                ts = trimmed.split(":", 1)[1].strip().rstrip("sS").strip()
                try:
                    timeout = int(ts)
                except ValueError:
                    pass
            continue
        req_lines.append(ln)

    if not req_lines:
        return "GET", "/", {}, "", timeout

    # 请求行
    parts = req_lines[0].strip().split()
    method = parts[0] if len(parts) >= 1 else "GET"
    path = parts[1] if len(parts) >= 2 else "/"

    headers = {}
    in_body = False
    body_lines = []
    for ln in req_lines[1:]:
        if not in_body:
            if ln.strip() == "":
                in_body = True
                continue
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip()] = v.strip()
        else:
            body_lines.append(ln)

    return method, path, headers, "\n".join(body_lines), timeout

def load_pocs(poc_dir: str) -> list:
    """从目录加载所有 POC"""
    pocs = []
    errors = []
    poc_path = Path(poc_dir)
    if not poc_path.exists():
        print(f"[!] POC 目录不存在: {poc_dir}")
        return pocs

    yaml_files = sorted(poc_path.glob("*.yaml")) + sorted(poc_path.glob("*.yml"))
    print(f"[*] 发现 {len(yaml_files)} 个 POC 文件")

    for yf in yaml_files:
        try:
            with open(yf, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if raw and isinstance(raw, dict):
                pocs.append(POC(raw))
            else:
                errors.append(f"{yf.name}: 空或格式错误")
        except Exception as e:
            errors.append(f"{yf.name}: {e}")

    if errors:
        print(f"[!] {len(errors)} 个 POC 加载失败:")
        for e in errors[:5]:
            print(f"    - {e}")
        if len(errors) > 5:
            print(f"    ... 还有 {len(errors) - 5} 个")

    print(f"[✓] 成功加载 {len(pocs)} 个 POC")
    return pocs

# ── 变量替换 ───────────────────────────────────────────────
import random
import string

def rand_string(n=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def expand_vars(target_url: str, s: str) -> str:
    """替换 POC 模板变量"""
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.netloc
    scheme = parsed.scheme

    replacements = {
        "{{baseURL}}": base_url, "{{BaseURL}}": base_url,
        "{{RootURL}}": base_url, "{{rootURL}}": base_url,
        "{{host}}": host, "{{Host}}": host,
        "{{Hostname}}": host, "{{hostname}}": host,
        "{{scheme}}": scheme,
        "{{rand}}": str(random.randint(0, 99999)),
        "{{randstr}}": rand_string(8),
    }
    for k, v in replacements.items():
        s = s.replace(k, v)
    return s

# ─── HTTP 客户端 ────────────────────────────────────────────
def decode_body(b: bytes, content_type: str) -> str:
    """检测 charset 并转码（GBK/GB2312 → UTF-8）"""
    cs = ""
    m = re.search(r'charset\s*=\s*["\']?([a-zA-Z0-9_-]+)', content_type, re.IGNORECASE)
    if m:
        cs = m.group(1).lower()

    # 也尝试从 HTML meta 检测
    if not cs and len(b) > 0:
        m2 = re.search(rb'<meta[^>]+charset\s*=\s*["\']?([a-zA-Z0-9_-]+)', b[:2048], re.IGNORECASE)
        if m2:
            cs = m2.group(1).decode().lower()

    if cs in ("gbk", "gb2312", "gb18030", "cp936"):
        try:
            return b.decode("gbk", errors="replace")
        except Exception:
            pass
    return b.decode("utf-8", errors="replace")

def http_request(method: str, url: str, headers: dict, body: str, timeout: int, max_redirects: int) -> dict:
    """发送 HTTP 请求"""
    try:
        sess = requests.Session()
        sess.max_redirects = max_redirects
        resp = sess.request(
            method=method,
            url=url,
            headers=headers,
            data=body.encode("utf-8") if body else None,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        body_str = decode_body(resp.content, resp.headers.get("Content-Type", ""))
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": body_str,
            "body_bytes": resp.content,
            "url": resp.url,
        }
    except requests.exceptions.Timeout:
        return {"status_code": 0, "headers": {}, "body": "", "body_bytes": b"", "url": url, "error": "timeout"}
    except Exception as e:
        return {"status_code": 0, "headers": {}, "body": "", "body_bytes": b"", "url": url, "error": str(e)}

# ─── POC 执行引擎 ───────────────────────────────────────────
def run_poc(target_url: str, poc: POC) -> list:
    """对目标执行单个 POC，返回 Finding 列表"""
    findings = []

    for req in poc.requests:
        # 处理 raw 格式
        if req.raw:
            steps = []
            for raw in req.raw:
                method, path, headers, body, timeout = parse_raw_request(raw)
                steps.append({
                    "method": method,
                    "path": expand_vars(target_url, path),
                    "headers": headers,
                    "body": expand_vars(target_url, body),
                    "timeout": timeout or req.timeout,
                })
        else:
            # 简化格式
            path = expand_vars(target_url, req.path.first())
            if not path.startswith("http"):
                parsed = urlparse(target_url)
                path = f"{parsed.scheme}://{parsed.netloc}/{path.lstrip('/')}"
            steps = [{
                "method": req.method,
                "path": path,
                "headers": req.headers,
                "body": expand_vars(target_url, req.body),
                "timeout": req.timeout,
            }]

        # 执行所有步骤
        last_resp = None
        all_ok = True
        for step in steps:
            resp = http_request(
                method=step["method"],
                url=step["path"],
                headers=step["headers"],
                body=step["body"],
                timeout=step["timeout"],
                max_redirects=req.max_redirects,
            )
            last_resp = resp
            if resp["status_code"] == 0:
                all_ok = False
                break

        if not all_ok or last_resp is None:
            continue

        # 评估匹配器
        matched = evaluate_matchers(req, last_resp)
        if matched:
            # 提取证据
            evidence = []
            for ext in req.extractors:
                v = ext.extract(last_resp["body"], last_resp["headers"])
                if v:
                    evidence.append(v)

            if not evidence and last_resp["body"]:
                evidence.append(last_resp["body"][:200])

            finding = {
                "poc_id": poc.id,
                "target": target_url,
                "url": last_resp["url"],
                "name": poc.name,
                "severity": poc.severity,
                "description": poc.description,
                "evidence": " | ".join(evidence),
                "status_code": last_resp["status_code"],
                "timestamp": datetime.now().isoformat(),
            }
            findings.append(finding)

    return findings

def evaluate_matchers(req: POCRequest, resp: dict) -> bool:
    """评估匹配器"""
    if not req.matchers:
        return True  # 无匹配器 = 只要请求成功就算命中

    cond = req.matchers_condition.lower()
    if cond == "or":
        return any(m.match(resp["status_code"], resp["body"], resp["headers"]) for m in req.matchers)
    else:
        return all(m.match(resp["status_code"], resp["body"], resp["headers"]) for m in req.matchers)

# ─── 扫描调度 ───────────────────────────────────────────────
def scan(target_url: str, pocs: list, interval: float = 2.0, ai_analyze: bool = False) -> list:
    """批量扫描目标"""
    # 按危害级别排序
    pocs_sorted = sorted(pocs, key=lambda p: p.severity_rank())

    print(f"\n{'='*60}")
    print(f"  目标: {target_url}")
    print(f"  POC 数量: {len(pocs_sorted)}")
    print(f"  间隔: {interval}s")
    print(f"  AI 分析: {'开启' if ai_analyze else '关闭'}")
    print(f"{'='*60}\n")

    all_findings = []
    req_count = 0

    for i, poc in enumerate(pocs_sorted):
        print(f"[{i+1}/{len(pocs_sorted)}] {poc.name} [{poc.severity.upper()}]", end=" ")

        findings = run_poc(target_url, poc)
        req_count += len(poc.requests)

        if findings:
            print(f"✓ 命中! ({len(findings)} 个发现)")
            for f in findings:
                print(f"    → {f['url']} (HTTP {f['status_code']})")
                print(f"    证据: {f['evidence'][:100]}")
            all_findings.extend(findings)
        else:
            print("✗ 未命中")

        # 间隔控制（最后一个不等待）
        if i < len(pocs_sorted) - 1:
            time.sleep(interval)

    # AI 分析
    if ai_analyze and all_findings:
        print(f"\n{'='*60}")
        print("  AI 分析中...")
        print(f"{'='*60}\n")

        summary = f"目标 {target_url} 扫描发现 {len(all_findings)} 个漏洞:\n"
        for f in all_findings:
            summary += f"- [{f['severity'].upper()}] {f['name']}: {f['evidence'][:100]}\n"
        summary += "\n请分析这些漏洞的风险等级、利用难度和修复建议。"

        ai_result = call_ai(summary)
        print(ai_result)

    # 汇总
    print(f"\n{'='*60}")
    print(f"  扫描完成!")
    print(f"  总请求数: {req_count}")
    print(f"  发现漏洞: {len(all_findings)}")
    if all_findings:
        by_sev = {}
        for f in all_findings:
            sev = f["severity"]
            by_sev[sev] = by_sev.get(sev, 0) + 1
        print(f"  按危害级别: {', '.join(f'{k.upper()}:{v}' for k, v in sorted(by_sev.items()))}")
    print(f"{'='*60}\n")

    return all_findings

# ─── CLI 入口 ───────────────────────────────────────────────
def cmd_scan(args):
    """scan 命令"""
    target = args.target
    poc_dir = args.pocs or POC_DIR
    interval = args.interval
    ai_analyze = args.ai

    print(f"[*] 加载 POC 库: {poc_dir}")
    pocs = load_pocs(poc_dir)
    if not pocs:
        print("[!] 未找到 POC，退出")
        return

    scan(target, pocs, interval, ai_analyze)

def cmd_list(args):
    """list 命令"""
    poc_dir = args.pocs or POC_DIR
    pocs = load_pocs(poc_dir)

    print(f"\n{'ID':<40} {'名称':<30} {'危害':<10}")
    print("-" * 80)
    for p in sorted(pocs, key=lambda x: x.severity_rank()):
        print(f"{p.id:<40} {p.name:<30} {p.severity.upper():<10}")
    print(f"\n共 {len(pocs)} 个 POC")

def cmd_config(args):
    """配置 AI"""
    config_ai_interactive()

def cmd_help(args):
    """帮助"""
    print("""
aivuln CLI — Python 版漏洞扫描工具

用法:
  python vuln_cli.py scan <target> [选项]    扫描目标
  python vuln_cli.py list [选项]             列出 POC
  python vuln_cli.py /ai                     配置 AI
  python vuln_cli.py /AI配置                 配置 AI（中文）
  python vuln_cli.py help                    显示帮助

scan 选项:
  --pocs <dir>      POC 目录 (默认: E:\\AI-Tools\\pocs)
  --interval <sec>  POC 执行间隔 (默认: 2 秒)
  --ai              启用 AI 分析

示例:
  python vuln_cli.py scan http://127.0.0.1:8080
  python vuln_cli.py scan http://target.com --pocs ./my_pocs --interval 1
  python vuln_cli.py scan http://target.com --ai
  python vuln_cli.py /ai
""")

def main():
    # 处理 /ai 和 /AI配置 快捷命令
    if len(sys.argv) > 1 and sys.argv[1] in ("/ai", "/AI配置"):
        config_ai_interactive()
        return

    parser = argparse.ArgumentParser(description="aivuln CLI - Python 版漏洞扫描工具")
    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # scan
    p_scan = subparsers.add_parser("scan", help="扫描目标")
    p_scan.add_argument("target", help="目标 URL")
    p_scan.add_argument("--pocs", help="POC 目录")
    p_scan.add_argument("--interval", type=float, default=2.0, help="POC 执行间隔（秒）")
    p_scan.add_argument("--ai", action="store_true", help="启用 AI 分析")

    # list
    p_list = subparsers.add_parser("list", help="列出 POC")
    p_list.add_argument("--pocs", help="POC 目录")

    # help
    subparsers.add_parser("help", help="显示帮助")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "help" or args.command is None:
        cmd_help(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
