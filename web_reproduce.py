#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web模块 - 浏览器自动复现
────────────────────────────────────────────────────────
使用 Playwright + 系统 Edge/Chrome 在真实浏览器中复现扫描命中的漏洞。

复现逻辑(常规, 非AI):
  - GET  型漏洞: 直接导航到含 payload 的完整 URL
  - POST 型漏洞: 先访问目标站点获取同源会话, 再通过 fetch 发送原始 POST
  - 不看状态码: 判定不依赖 HTTP 状态码(200/403/423 都可能是漏洞页面)
  - 只看危害:   根据 POC 危害特征词(匹配器 words/regex)检查响应内容,
                确认"是否有危害", 有危害的链接红色标注
  - 停在页面:   复现后浏览器不退出, 人工确认后按回车关闭

依赖:
  pip install playwright
  (浏览器复用系统 Edge, 无需执行 playwright install)
"""

import re
import time
from urllib.parse import urlparse

# ANSI 红色/黄色标注
_RED = "\033[91m"
_YEL = "\033[93m"
_GRN = "\033[92m"
_END = "\033[0m"

# 需要传递给浏览器的请求头白名单
_PASS_HEADERS = ("content-type", "cookie", "authorization", "x-requested-with", "referer")

# POST 复现用 JS: 在目标域内发起 fetch, 保存响应供危害判定, 并渲染到页面
_FETCH_JS = r"""
async (args) => {
  const opts = { method: args.method, headers: args.headers };
  if (args.body) opts.body = args.body;
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
                              .replace(/>/g, '&gt;');
  document.body.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.style.cssText = 'font-family:Consolas,monospace;padding:20px;background:#0d1117;color:#c9d1d9;min-height:100vh;';
  wrap.innerHTML = '<h2 style="color:#f85149">漏洞复现结果</h2>'
    + '<p><b>请求:</b> ' + esc(args.method) + ' ' + esc(args.url) + '</p>';
  try {
    const r = await fetch(args.url, opts);
    const t = await r.text();
    window.__repro_status = r.status;
    window.__repro_body = t;
    wrap.innerHTML += '<p><b>响应:</b> HTTP ' + r.status + ' ' + esc(r.statusText) + ' (' + t.length + ' 字符)</p>'
      + '<pre style="white-space:pre-wrap;word-break:break-all;border:1px solid #30363d;padding:10px;border-radius:6px;background:#161b22;max-height:70vh;overflow:auto;">'
      + esc(t.slice(0, 8000)) + '</pre>';
  } catch (e) {
    window.__repro_status = -1;
    window.__repro_body = null;
    wrap.innerHTML += '<p style="color:#e3b341"><b>提示:</b> 请求已发出但无法读取响应(跨域/CORS或网络错误), 请直接在地址栏/控制台确认现象。</p>'
      + '<p style="color:#e3b341">错误信息: ' + esc(e.message) + '</p>';
  }
  document.title = '漏洞复现 - ' + args.method + ' ' + esc(args.url);
  document.body.appendChild(wrap);
}
"""


def _launch(headless: bool = False):
    """启动 Playwright 浏览器: 优先系统 Edge, 回退 Chrome, 最后默认 chromium"""
    from playwright.sync_api import sync_playwright

    pw = sync_playwright().start()
    last_err = None
    for channel in ("msedge", "chrome"):
        try:
            browser = pw.chromium.launch(channel=channel, headless=headless)
            print(f"[浏览器复现] 已启动浏览器 (channel={channel}, headless={headless})")
            return pw, browser
        except Exception as e:  # noqa: BLE001
            last_err = e
    try:
        browser = pw.chromium.launch(headless=headless)
        print("[浏览器复现] 已启动默认 Chromium 浏览器")
        return pw, browser
    except Exception as e:  # noqa: BLE001
        pw.stop()
        raise RuntimeError(f"无法启动浏览器: {last_err}\n兜底启动也失败: {e}")


def _filter_headers(headers: dict) -> dict:
    """只保留 POC 请求中需要带进浏览器的头"""
    if not headers:
        return {}
    out = {}
    for k, v in headers.items():
        if k.lower() in _PASS_HEADERS and v:
            out[k] = v
    return out


def _check_harm(content: str, match_words: list, match_regex: list):
    """只看内容特征判定是否"有危害", 不看状态码

    :return: True=确认有危害 / False=未发现危害特征 / None=无法判定(无特征词)
    """
    if not match_words and not match_regex:
        return None
    if not content:
        return None
    c = content.lower()
    for w in match_words:
        if w and w.lower() in c:
            return True
    for p in match_regex:
        try:
            if re.search(p, content, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def reproduce(finding: dict, wait_sec: float = 3.0, headless: bool = False,
              hold_on: bool = True) -> dict:
    """在浏览器中复现漏洞并停在页面

    :param finding: run_poc 返回的命中记录
                    (url/request_method/request_body/request_headers/match_words/match_regex)
    :param wait_sec: 复现后停留观察秒数
    :param headless: 无头模式(不弹窗)
    :param hold_on: 是否等待人工按回车后关闭浏览器
    :return: {"url": str, "harm": True|False|None, "detail": str}
             harm=None 表示无特征词或无法读取响应, 需人工确认
    """
    url = finding.get("url") or ""
    result = {"url": url, "harm": None, "detail": ""}
    if not url:
        print("[浏览器复现] ✗ finding 缺少 url, 无法复现")
        return result

    method = (finding.get("request_method") or "GET").upper()
    body = finding.get("request_body") or ""
    headers = _filter_headers(finding.get("request_headers") or {})
    match_words = finding.get("match_words") or []
    match_regex = finding.get("match_regex") or []

    print(f"[浏览器复现] {'='*50}")
    print(f"[浏览器复现] 漏洞: {finding.get('name', '未知')} ({finding.get('severity', '?')})")
    print(f"[浏览器复现] 请求: {method} {url}")
    if method != "GET":
        print(f"[浏览器复现] Body: {body[:200]}")
    if match_words:
        print(f"[浏览器复现] 危害特征: {match_words[:6]}")
    print(f"[浏览器复现] 启动浏览器复现中...")

    pw, browser = _launch(headless)
    context = browser.new_context()
    page = context.new_page()
    try:
        if method == "GET":
            # 直接导航到含 payload 的完整 URL (不看状态码, 只看内容特征)
            page.goto(url, timeout=30000, wait_until="domcontentloaded")
            page.wait_for_timeout(int(wait_sec * 1000))
            content = page.content()
            harm = _check_harm(content, match_words, match_regex)
            print(f"[浏览器复现] ✓ GET 复现完成, 页面已停留在: {url}")
        else:
            # 先访问目标站根路径拿同源会话
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            try:
                page.goto(origin, timeout=30000, wait_until="domcontentloaded")
            except Exception:  # noqa: BLE001
                pass
            # 同源内用 fetch 发送原始请求
            page.evaluate(_FETCH_JS, {
                "method": method,
                "url": url,
                "headers": headers,
                "body": body,
            })
            page.wait_for_timeout(int(wait_sec * 1000))
            resp_body = page.evaluate("() => window.__repro_body")
            resp_status = page.evaluate("() => window.__repro_status")
            print(f"[浏览器复现] ✓ POST 复现完成, 请求已发送 (HTTP {resp_status})")
            if resp_body is None:
                harm = None  # 跨域/无法读取响应, 待人工确认
            else:
                harm = _check_harm(resp_body, match_words, match_regex)

        # ── 危害判定输出 (不看状态码, 只看有没有危害) ──
        if harm is True:
            result["harm"] = True
            result["detail"] = "响应中包含危害特征词, 确认存在危害"
            print(f"{_RED}[浏览器复现] ▶ 危害确认! 该链接存在实际危害: {url}{_END}")
        elif harm is False:
            result["harm"] = False
            result["detail"] = "未发现危害特征词"
            print(f"{_GRN}[浏览器复现] ○ 未发现危害特征: {url}{_END}")
        else:
            result["harm"] = None
            result["detail"] = "无特征词或无法读取响应, 需人工确认"
            print(f"{_YEL}[浏览器复现] ? 无法自动判定, 需人工确认: {url}{_END}")

        if headless:
            print("[浏览器复现] ✓ 无头模式复现完成, 关闭浏览器")
            return result

        # ── 停在页面, 不退出 ──
        print(f"[浏览器复现] ─────────────────────────────────────────")
        print(f"[浏览器复现]  浏览器已停留在漏洞页面, 请人工确认现象.")
        print(f"[浏览器复现]  按回车键关闭浏览器并继续...")
        if hold_on:
            try:
                input()
            except EOFError:
                print("[浏览器复现] 非交互环境, 3 秒后自动关闭")
                time.sleep(3)
        return result
    finally:
        try:
            browser.close()
            pw.stop()
        except Exception:  # noqa: BLE001
            pass


def reproduce_all(findings: list, wait_sec: float = 3.0, headless: bool = False) -> list:
    """依次复现多个命中记录, 每个等待人工确认

    :return: 确认存在危害的链接列表 (含漏洞名/URL)
    """
    if not findings:
        return []
    harm_links = []
    for i, f in enumerate(findings, 1):
        print(f"\n[浏览器复现] [{i}/{len(findings)}]")
        try:
            r = reproduce(f, wait_sec=wait_sec, headless=headless)
            if r.get("harm") is True:
                harm_links.append({
                    "url": r.get("url"),
                    "name": f.get("name", ""),
                    "severity": f.get("severity", ""),
                })
        except Exception as e:  # noqa: BLE001
            print(f"[浏览器复现] ✗ 复现失败: {e}")

    # 汇总危害链接标注
    if harm_links:
        print(f"\n[浏览器复现] {_RED}{'='*50}{_END}")
        print(f"{_RED}[浏览器复现] ★ 确认存在危害的链接共 {len(harm_links)} 个:{_END}")
        for h in harm_links:
            print(f"{_RED}   ▶ [{h['severity'].upper()}] {h['name']}{_END}")
            print(f"{_RED}     {h['url']}{_END}")
        print(f"{_RED}{'='*50}{_END}")
    else:
        print(f"\n[浏览器复现] 未确认到明确危害链接(需人工确认的请查看上方输出)")
    return harm_links
