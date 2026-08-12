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
PAYLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads")
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

# AI 调用超时（秒）与重试次数
AI_TIMEOUT = 45
AI_MAX_RETRIES = 0  # 0=不重试，快速暴露错误避免长时间卡住

def call_ai(prompt: str, verbose: bool = False, max_tokens: int = None) -> str:
    """调用 AI API 进行分析
    :param max_tokens: 限制AI输出长度（token），可显著加快响应；None=不限制
    """
    cfg = load_ai_config()
    if not cfg.get("api_url") or not cfg.get("api_key"):
        return "[!] AI 未配置，请先运行 /ai 配置"

    api_url = cfg["api_url"].rstrip("/")
    model = cfg.get("model", "gpt-3.5-turbo")

    if verbose:
        print(f"    │ 请求: POST {api_url}/chat/completions")
        print(f"    │ 模型: {model}" + (f" (max_tokens={max_tokens})" if max_tokens else ""))
        print(f"    │ 提示词: {prompt[:150].replace(chr(10), ' ')}...")
        print(f"    │ 等待 AI 响应中 (超时 {AI_TIMEOUT}s，若模型名/Key错误将快速报错)...")

    try:
        from openai import OpenAI
        # max_retries=0 禁用自动重试，避免无效Key/模型时反复退避重试导致长时间卡住
        client = OpenAI(
            base_url=cfg["api_url"],
            api_key=cfg["api_key"],
            timeout=AI_TIMEOUT,
            max_retries=AI_MAX_RETRIES,
        )
        kwargs = dict(model=model, messages=[{"role": "user", "content": prompt}], timeout=AI_TIMEOUT)
        if max_tokens:
            kwargs["max_tokens"] = max_tokens
        resp = client.chat.completions.create(**kwargs)
        content = resp.choices[0].message.content
        if verbose:
            print(f"    │ ✓ 收到响应 ({len(content)} 字符)")
        return content
    except ImportError:
        # 不用 openai 库，直接用 requests
        import requests as req
        headers = {
            "Authorization": f"Bearer {cfg['api_key']}",
            "Content-Type": "application/json",
        }
        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        }
        if max_tokens:
            data["max_tokens"] = max_tokens
        r = req.post(f"{api_url}/chat/completions", json=data, headers=headers, timeout=AI_TIMEOUT)
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
        if verbose:
            print(f"    │ ✓ 收到响应 ({len(content)} 字符)")
        return content
    except Exception as e:
        if verbose:
            print(f"    │ ✗ 调用异常: {e}")
            print(f"    │   提示: 若报错包含 model/404 相关，请检查模型名是否正确")
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
def scan(target_url: str, pocs: list, interval: float = 2.0, ai_analyze: bool = False, ai_payload: bool = False, ai_payload_interval: int = 10) -> list:
    """批量扫描目标"""
    # 按危害级别排序
    pocs_sorted = sorted(pocs, key=lambda p: p.severity_rank())

    print(f"\n{'='*60}")
    print(f"  目标: {target_url}")
    print(f"  POC 数量: {len(pocs_sorted)}")
    print(f"  间隔: {interval}s")
    print(f"  AI 分析: {'开启' if ai_analyze else '关闭'}")
    print(f"  AI Payload: {'开启' if ai_payload else '关闭'}")
    if ai_payload:
        print(f"  AI Payload 间隔: 每 {ai_payload_interval} 个POC")
    print(f"{'='*60}\n")

    all_findings = []
    req_count = 0
    temp_payload_files = []  # 记录临时payload文件
    ai_configured = None  # AI配置状态缓存，None=未检查

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

        # AI 动态生成 Payload
        if ai_payload and (i + 1) % ai_payload_interval == 0:
            print(f"\n  [AI] 生成针对性 Payload...")
            poc_context = f"当前POC: {poc.id} - {poc.name} ({poc.severity})\n已扫描 {i+1}/{len(pocs_sorted)} 个POC"
            if all_findings:
                poc_context += f"\n已发现 {len(all_findings)} 个漏洞"

            ai_payloads = generate_ai_payload(target_url, poc_context)
            if ai_payloads:
                temp_file = save_temp_payload(ai_payloads, target_url)
                temp_payload_files.append(temp_file)
                print(f"    │ 已保存临时文件: {temp_file}")

                # 执行AI生成的payload
                print(f"    │ 执行 Payload 测试中...")
                payload_findings = execute_ai_payloads(target_url, ai_payloads, interval)
                if payload_findings:
                    print(f"    │ ✓ 发现 {len(payload_findings)} 个潜在漏洞!")
                    all_findings.extend(payload_findings)
                else:
                    print(f"    │ ✗ 未发现漏洞")
            else:
                print(f"  [AI] ✗ Payload 生成失败")
                # AI未配置时只提示一次，避免重复刷屏
                if ai_configured is None:
                    cfg = load_ai_config()
                    ai_configured = bool(cfg.get("api_url") and cfg.get("api_key"))
                if not ai_configured:
                    print(f"  [!] 提示: 配置 AI 后重新运行 --ai-payload 即可启用动态 Payload (python vuln_cli.py /ai)")
                    ai_payload = False  # 停止后续生成尝试
            print()

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

    # 清理临时文件
    if temp_payload_files:
        print(f"\n[*] 清理临时 Payload 文件...")
        for temp_file in temp_payload_files:
            try:
                os.remove(temp_file)
                print(f"  ✓ 已删除: {os.path.basename(temp_file)}")
            except Exception as e:
                print(f"  ✗ 删除失败: {os.path.basename(temp_file)} - {e}")

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

def execute_ai_payloads(target_url: str, payloads: list, interval: float = 2.0) -> list:
    """执行AI生成的payload"""
    findings = []
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    print(f"    │ 开始执行 {len(payloads)} 条 Payload (间隔 {interval}s)")

    for i, payload_line in enumerate(payloads, 1):
        try:
            parts = payload_line.split("|")
            # 兼容 3字段(GET无body) 和 4字段(POST有body) 格式
            if len(parts) == 3:
                method, path, match_condition = parts[0], parts[1], parts[2]
                body = ""
            elif len(parts) == 4:
                method, path, body, match_condition = parts
            else:
                print(f"    │ [{i}/{len(payloads)}] ✗ 格式异常，跳过: {payload_line[:60]}")
                continue

            method = method.strip().upper()
            path = path.strip()
            body = body.strip()
            match_condition = match_condition.strip()

            # 构造完整URL
            if not path.startswith("http"):
                if not path.startswith("/"):
                    path = "/" + path
                full_url = base_url + path
            else:
                full_url = path

            print(f"    │ [{i}/{len(payloads)}] {method} {full_url}", end=" ")

            # 发送请求
            resp = http_request(method, full_url, {}, body, 10, 3)

            if resp["status_code"] == 0:
                print(f"✗ 请求失败: {resp.get('error', 'unknown')}")
                continue

            # 解析匹配条件
            matched = evaluate_match_condition(match_condition, resp)

            if matched:
                print(f"✓ 命中! (HTTP {resp['status_code']}, 条件: {match_condition[:40]})")
                findings.append({
                    "poc_id": "ai-generated-payload",
                    "target": target_url,
                    "url": full_url,
                    "name": f"AI Payload - {method} {path[:50]}",
                    "severity": "medium",
                    "description": f"AI生成的Payload: {payload_line}",
                    "evidence": resp["body"][:200],
                    "status_code": resp["status_code"],
                    "timestamp": datetime.now().isoformat(),
                })
            else:
                print(f"✗ 未命中 (HTTP {resp['status_code']})")

            time.sleep(interval)

        except Exception:
            continue

    return findings

def evaluate_match_condition(condition: str, resp: dict) -> bool:
    """评估匹配条件"""
    try:
        condition = condition.strip()

        # 解析 status_code==N
        if "status_code==" in condition:
            match = re.search(r'status_code==(\d+)', condition)
            if match:
                expected_status = int(match.group(1))
                if resp["status_code"] != expected_status:
                    return False

        # 解析 body contains "xxx"
        if "body contains" in condition:
            match = re.search(r'body contains "([^"]+)"', condition)
            if match:
                keyword = match.group(1)
                if keyword.lower() not in resp["body"].lower():
                    return False

        # 解析 body!=""
        if "body!=\"\"" in condition:
            if not resp["body"]:
                return False

        return True

    except Exception:
        return False

# ─── AI Payload 生成引擎 ────────────────────────────────────
def generate_ai_payload(target_url: str, poc_context: str, vuln_type: str = None) -> list:
    """
    调用AI生成针对目标的payload
    :param target_url: 目标URL
    :param poc_context: 当前POC上下文（POC ID、名称、类型等）
    :param vuln_type: 指定漏洞类型（sqli/xss/lfi/rce等），None则由AI判断
    :return: payload列表
    """
    cfg = load_ai_config()
    if not cfg.get("api_url") or not cfg.get("api_key"):
        print(f"[!] AI 未配置，无法生成 Payload。请先运行: python vuln_cli.py /ai")
        return []

    prompt = f"""你是一个Web安全专家，需要根据以下信息生成渗透测试payload。

目标URL: {target_url}
当前POC信息: {poc_context}
"""
    if vuln_type:
        prompt += f"漏洞类型: {vuln_type}\n"

    prompt += """
请生成2-3个针对性的payload，严格按以下格式输出（每行一个，不要任何其他文字）：

格式: 方法|路径|请求体|匹配条件

规则：
- 方法: GET 或 POST
- 路径: 以 / 开头的相对路径，可在参数中注入 payload
- 请求体: GET 请求留空（字段保留但为空）
- 匹配条件: 使用 status_code==状态码 和/或 body contains "关键字"，多个条件用 && 连接

示例:
GET|/api/user?id=1' AND SLEEP(3)-- -||status_code==200
POST|/login|username=admin' OR '1'='1&password=x|status_code==200 && body contains "token"
GET|/download?file=../../../../etc/passwd||status_code==200 && body contains "root:"

要求：
1. 结合目标URL路径和当前POC所反映的漏洞类型生成
2. 覆盖绕过技巧（大小写、注释符、编码、参数污染等）
3. 匹配条件要精确，能有效确认漏洞存在
4. 只输出payload行，禁止输出解释、说明、代码块标记或任何多余文字
"""

    # 过程日志
    print(f"    │ 目标      : {target_url}")
    if vuln_type:
        print(f"    │ 漏洞类型  : {vuln_type}")
    print(f"    │ POC上下文 : {poc_context.splitlines()[0] if poc_context else ''}")
    print(f"    │ 调用AI生成 Payload 中 (通常 5~30s，请耐心等待)...")

    try:
        t0 = time.time()
        # 限制输出token(600)，2-3个payload足够，显著加快响应速度
        result = call_ai(prompt, verbose=True, max_tokens=600)
        elapsed = time.time() - t0

        if result.startswith("[!]"):
            print(f"    │ ✗ {result}")
            return []

        print(f"    │ ✓ AI 响应完成，耗时 {elapsed:.1f}s")

        # 空响应检查：reasoner/无效模型可能返回空内容
        if not result or not result.strip():
            print(f"    │ ✗ AI 返回了空内容！模型可能无效（如 reasoner 类模型思考耗尽token）")
            print(f"    │   建议将模型改为官方对话模型: deepseek-chat")
            return []

        # 剥离可能的 markdown 代码块标记
        result = re.sub(r'```\w*', '', result)

        # 解析AI返回的payload
        payloads = []
        for line in result.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and "|" in line:
                payloads.append(line)

        print(f"    │ 解析: 共 {len(result.strip().splitlines())} 行，识别出 {len(payloads)} 条有效 Payload")

        if not payloads:
            print(f"    │ ✗ 未解析到有效 Payload，AI 原始返回:")
            for ln in result.strip().splitlines()[:10]:
                print(f"    │   {ln[:120]}")
            return []

        for idx, p in enumerate(payloads, 1):
            print(f"    │   [{idx}] {p[:110]}{'...' if len(p) > 110 else ''}")

        return payloads[:5]  # 最多5个
    except Exception as e:
        print(f"[!] AI生成payload失败: {e}")
        return []

def save_temp_payload(payloads: list, target: str) -> str:
    """保存payload到临时文件"""
    import tempfile
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".temp")
    os.makedirs(temp_dir, exist_ok=True)

    # 生成文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_hash = hash(target) % 10000
    filename = f"ai_payload_{target_hash}_{timestamp}.txt"
    filepath = os.path.join(temp_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# AI生成的Payload - {datetime.now().isoformat()}\n")
        f.write(f"# 目标: {target}\n")
        f.write("# 格式: 方法|路径|请求体|匹配条件\n\n")
        for p in payloads:
            f.write(p + "\n")

    return filepath

def cleanup_temp_payloads(max_age_hours: int = 24):
    """清理过期的临时payload文件"""
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".temp")
    if not os.path.exists(temp_dir):
        return

    now = time.time()
    for f in os.listdir(temp_dir):
        filepath = os.path.join(temp_dir, f)
        if os.path.isfile(filepath):
            age_hours = (now - os.path.getmtime(filepath)) / 3600
            if age_hours > max_age_hours:
                try:
                    os.remove(filepath)
                except:
                    pass

# ─── Payload 挖掘引擎 ──────────────────────────────────────
class PayloadMatcher:
    """Payload 匹配器 - 复用 POC 的匹配器机制"""
    
    # SQL 注入错误特征
    SQLI_PATTERNS = [
        r"sql syntax.*mysql",
        r"warning.*mysql",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"mysql_query",
        r"pg_query",
        r"pg_fetch",
        r"sqlite_query",
        r"ORA-\d{5}",
        r"Oracle error",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"Unclosed quotation mark",
        r"unterminated.*string",
        r"SQL command not properly ended",
        r"Syntax error.*in query expression",
        r"postgresql.*error",
        r"sqlite3\.",
        r"sqlite\.",
    ]
    
    # XSS 反射检测（payload 被原样返回）
    XSS_INDICATORS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "onerror=alert(1)",
        "onload=alert(1)",
        "ontoggle=alert(1)",
        "onfocus=alert(1)",
        "onmouseover=\"alert(1)",
        "onmouseover='alert(1)",
    ]
    
    # 本地文件包含特征
    LFI_PATTERNS = {
        "passwd": [r"root:.*:0:0:", r"/bin/bash", r"/bin/sh"],
        "win.ini": [r"\[extensions\]", r"\[fonts\]", r"\[mci extensions\]"],
        "phpinfo": [r"phpinfo\(\)", r"PHP Version", r"php\.info"],
        "env": [r"APP_ENV=", r"DB_PASSWORD=", r"APP_KEY="],
    }
    
    # 命令注入特征
    CMDI_PATTERNS = [
        r"uid=\d+",
        r"root:.*:0:0:",
        r"Windows IP Configuration",
        r"Linux.*\d+\.\d+\.\d+",
        r"PING.*bytes from",
        r"Reply from \d+\.\d+\.\d+\.\d+",
        r"vol in drive",
        r"Directory of",
    ]
    
    def __init__(self, payload_type: str):
        self.type = payload_type.lower()
    
    def match(self, payload: str, status_code: int, body: str, headers: dict) -> bool:
        """检测响应是否匹配漏洞特征"""
        if self.type == "sqli":
            return self._match_sqli(body)
        elif self.type == "xss":
            return self._match_xss(payload, body)
        elif self.type == "lfi":
            return self._match_lfi(body)
        elif self.type == "cmdi":
            return self._match_cmdi(body)
        return False
    
    def _match_sqli(self, body: str) -> bool:
        """SQL 注入检测"""
        body_lower = body.lower()
        for pattern in self.SQLI_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                return True
        return False
    
    def _match_xss(self, payload: str, body: str) -> bool:
        """XSS 检测 - payload 被反射"""
        # 检测 payload 是否被原样返回（未编码）
        if payload in body:
            return True
        # 检测常见的 XSS 指示器
        for indicator in self.XSS_INDICATORS:
            if indicator in body:
                return True
        return False
    
    def _match_lfi(self, body: str) -> bool:
        """LFI 检测"""
        for category, patterns in self.LFI_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return True
        return False
    
    def _match_cmdi(self, body: str) -> bool:
        """命令注入检测"""
        for pattern in self.CMDI_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False

def load_payloads(payload_file: str) -> list:
    """从文件加载 payload 列表"""
    payloads = []
    if not os.path.exists(payload_file):
        print(f"[!] Payload 文件不存在: {payload_file}")
        return payloads
    
    try:
        with open(payload_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.append(line)
        print(f"[✓] 加载 {len(payloads)} 个 payload")
    except Exception as e:
        print(f"[!] 加载 payload 失败: {e}")
    
    return payloads

def fuzz_target(target_url: str, payload_type: str, payloads: list, interval: float = 0.5) -> list:
    """使用 payload 对目标进行模糊测试"""
    findings = []
    matcher = PayloadMatcher(payload_type)
    
    # 解析目标 URL
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    query = parsed.query
    
    print(f"\n{'='*60}")
    print(f"  目标: {target_url}")
    print(f"  Payload 类型: {payload_type.upper()}")
    print(f"  Payload 数量: {len(payloads)}")
    print(f"  间隔: {interval}s")
    print(f"{'='*60}\n")
    
    for i, payload in enumerate(payloads):
        print(f"[{i+1}/{len(payloads)}] 测试: {payload[:50]}{'...' if len(payload) > 50 else ''}", end=" ")
        
        # 构造测试 URL
        if query:
            # URL 有参数，对每个参数注入 payload
            params = query.split("&")
            for param in params:
                if "=" in param:
                    key, _ = param.split("=", 1)
                    test_url = f"{base_url}{path}?{key}={payload}"
                    
                    resp = http_request("GET", test_url, {}, "", 10, 3)
                    
                    if resp["status_code"] != 0:
                        if matcher.match(payload, resp["status_code"], resp["body"], resp["headers"]):
                            print(f"✓ 命中!")
                            print(f"    → {test_url} (HTTP {resp['status_code']})")
                            findings.append({
                                "type": payload_type,
                                "payload": payload,
                                "url": test_url,
                                "status_code": resp["status_code"],
                                "evidence": resp["body"][:200],
                                "timestamp": datetime.now().isoformat(),
                            })
                            break  # 一个 payload 只报告一次
                    else:
                        print(f"✗ 请求失败")
        else:
            # URL 无参数，尝试在路径后注入
            test_url = f"{base_url}{path}/{payload}"
            resp = http_request("GET", test_url, {}, "", 10, 3)
            
            if resp["status_code"] != 0:
                if matcher.match(payload, resp["status_code"], resp["body"], resp["headers"]):
                    print(f"✓ 命中!")
                    print(f"    → {test_url} (HTTP {resp['status_code']})")
                    findings.append({
                        "type": payload_type,
                        "payload": payload,
                        "url": test_url,
                        "status_code": resp["status_code"],
                        "evidence": resp["body"][:200],
                        "timestamp": datetime.now().isoformat(),
                    })
                else:
                    print("✗ 未命中")
            else:
                print("✗ 请求失败")
        
        # 间隔控制
        if i < len(payloads) - 1:
            time.sleep(interval)
    
    # 汇总
    print(f"\n{'='*60}")
    print(f"  测试完成!")
    print(f"  总请求数: {len(payloads)}")
    print(f"  发现漏洞: {len(findings)}")
    print(f"{'='*60}\n")
    
    return findings

# ─── CLI 入口 ───────────────────────────────────────────────
def cmd_scan(args):
    """scan 命令"""
    target = args.target
    poc_dir = args.pocs or POC_DIR
    interval = args.interval
    ai_analyze = args.ai
    ai_payload = args.ai_payload
    ai_payload_interval = args.ai_payload_interval

    print(f"[*] 加载 POC 库: {poc_dir}")
    pocs = load_pocs(poc_dir)
    if not pocs:
        print("[!] 未找到 POC，退出")
        return

    scan(target, pocs, interval, ai_analyze, ai_payload, ai_payload_interval)

def cmd_payload(args):
    """payload 命令"""
    target = args.target
    payload_type = args.type.lower()
    payload_file = args.file or os.path.join(PAYLOAD_DIR, f"{payload_type}.txt")
    interval = args.interval
    
    print(f"[*] 加载 Payload: {payload_file}")
    payloads = load_payloads(payload_file)
    if not payloads:
        print("[!] 未找到 payload，退出")
        return
    
    findings = fuzz_target(target, payload_type, payloads, interval)
    
    if findings:
        print(f"\n[+] 发现 {len(findings)} 个潜在漏洞:")
        for f in findings:
            print(f"  - [{f['type'].upper()}] {f['payload'][:50]}")
            print(f"    URL: {f['url']}")

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
  python vuln_cli.py scan <target> [选项]       扫描目标（POC 模式）
  python vuln_cli.py payload <target> [选项]    Payload 挖掘模式
  python vuln_cli.py list [选项]                列出 POC
  python vuln_cli.py /ai                        配置 AI
  python vuln_cli.py /AI配置                    配置 AI（中文）
  python vuln_cli.py help                       显示帮助

scan 选项:
  --pocs <dir>              POC 目录 (默认: E:\\AI-Tools\\pocs)
  --interval <sec>          POC 执行间隔 (默认: 2 秒)
  --ai                      启用 AI 分析
  --ai-payload              启用 AI 动态生成 Payload
  --ai-payload-interval <n> 每隔 n 个 POC 生成一次 AI Payload (默认: 10)

payload 选项:
  --type <type>     Payload 类型: sqli/xss/lfi/cmdi (必填)
  --file <path>     自定义 payload 文件
  --interval <sec>  请求间隔 (默认: 0.5 秒)

示例:
  python vuln_cli.py scan http://127.0.0.1:8080
  python vuln_cli.py scan http://target.com --pocs ./my_pocs --interval 1
  python vuln_cli.py scan http://target.com --ai --ai-payload
  python vuln_cli.py scan http://target.com --ai-payload --ai-payload-interval 5
  python vuln_cli.py payload "http://target.com/page?id=1" --type sqli
  python vuln_cli.py payload "http://target.com/search?q=test" --type xss --interval 1
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
    p_scan.add_argument("--ai-payload", action="store_true", help="启用 AI 动态生成 Payload")
    p_scan.add_argument("--ai-payload-interval", type=int, default=10, help="每隔多少个 POC 生成一次 AI Payload（默认: 10）")

    # payload
    p_payload = subparsers.add_parser("payload", help="Payload 挖掘模式")
    p_payload.add_argument("target", help="目标 URL（带参数，如 http://target.com/page?id=1）")
    p_payload.add_argument("--type", required=True, help="Payload 类型: sqli/xss/lfi/cmdi")
    p_payload.add_argument("--file", help="自定义 payload 文件路径")
    p_payload.add_argument("--interval", type=float, default=0.5, help="请求间隔（秒）")

    # list
    p_list = subparsers.add_parser("list", help="列出 POC")
    p_list.add_argument("--pocs", help="POC 目录")

    # help
    subparsers.add_parser("help", help="显示帮助")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "payload":
        cmd_payload(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "help" or args.command is None:
        cmd_help(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
