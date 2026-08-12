# aivuln CLI - Python 版漏洞扫描工具

<div align="center">

**基于 Nuclei YAML 模板的自动化漏洞检测工具**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![POC Count](https://img.shields.io/badge/POCs-78-orange.svg)](pocs/)

</div>

---

## 📖 项目简介

aivuln CLI 是一个基于 Python 的自动化漏洞扫描工具，完全兼容 **Nuclei YAML 模板格式**。工具采用模块化设计，支持批量 POC 执行、智能匹配、AI 辅助分析、AI 动态生成 Payload、WAF 探测与绕过等功能。

### ✨ 核心特性

- 🎯 **Nuclei 兼容** - 完全支持 Nuclei YAML POC 格式（raw 原始报文 / word / status / regex / dsl 匹配器）
- 🔄 **批量扫描** - 自动加载并执行多个 POC，按危害级别（critical → low）排序，间隔可配置
- 🤖 **AI 分析** - 集成 AI 辅助漏洞分析（支持任意 OpenAI 兼容 API）
- 🧠 **AI 动态 Payload** - 扫描过程中 AI 根据 POC 上下文实时生成针对性 Payload 并执行测试
- 🛡️ **WAF 探测与绕过** - 自动识别目标 WAF 类型，4 种变形规则尝试绕过（URL 编码 / 双重编码 / 大小写 / 注释符）
- 🔍 **Payload 挖掘** - 独立的 Payload 模糊测试模式（sqli / xss / lfi / cmdi）
- 📂 **敏感文件扫描** - 探测 robots.txt / .env / .git / 备份文件等 16 个敏感路径
- 🔴 **红色标注** - 发现漏洞用红色字体高亮显示（支持 Windows 控制台 ANSI）
- 🌐 **编码自适应** - 自动检测 GBK/GB2312/GB18030/CP936 编码并转码为 UTF-8，解决中文乱码问题
- ⚡ **灵活配置** - 支持自定义 POC 目录、执行间隔、HTTP 超时等

---

## 🚀 快速开始

### 环境要求

- Python 3.8+
- pip 包管理器

### 安装依赖

```bash
pip install pyyaml requests
```

或使用提供的安装脚本：

```bash
# Windows
安装依赖.bat

# Linux/Mac
chmod +x install.sh && ./install.sh
```

### 基本使用

```bash
# 扫描目标
python vuln_cli.py scan http://target.com

# 列出所有 POC
python vuln_cli.py list

# WAF 探测与绕过测试
python vuln_cli.py waf http://target.com

# 敏感文件扫描（robots.txt/.env/.git等）
python vuln_cli.py sensitive http://target.com

# 查看帮助
python vuln_cli.py help
```

---

## 📚 详细使用教程

### 1. 扫描目标

#### 基础扫描

```bash
python vuln_cli.py scan http://192.168.1.100
```

#### 高级选项

```bash
# 指定 POC 目录（默认 E:\AI-Tools\pocs）
python vuln_cli.py scan http://target.com --pocs ./my_pocs

# 调整执行间隔（默认 2 秒）
python vuln_cli.py scan http://target.com --interval 1

# 启用 AI 分析（扫描结束后分析结果）
python vuln_cli.py scan http://target.com --ai

# 启用 AI 动态生成 Payload（每 10 个 POC 生成一次）
python vuln_cli.py scan http://target.com --ai-payload

# 调整 AI Payload 生成频率（每 5 个 POC）
python vuln_cli.py scan http://target.com --ai-payload --ai-payload-interval 5

# 扫描前自动探测目标 WAF
python vuln_cli.py scan http://target.com --waf-detect

# 探测 WAF 并自动尝试变形绕过被拦截的请求
python vuln_cli.py scan http://target.com --waf-detect --bypass

# POC 扫描前先进行敏感文件扫描
python vuln_cli.py scan http://target.com --sensitive

# 扫描结束后用浏览器自动复现命中的漏洞（停在页面，人工确认后回车继续）
# 判定不看状态码，只根据 POC 危害特征词确认"是否有危害"，有危害的链接红色标注
python vuln_cli.py scan http://target.com --browser

# 浏览器复现使用无头模式（不弹窗，自动化取证）
python vuln_cli.py scan http://target.com --browser --headless

# 组合使用
python vuln_cli.py scan http://target.com --pocs ./custom_pocs --interval 1 --ai --ai-payload --waf-detect --bypass --sensitive
```

### 2. 配置 AI

工具支持集成 AI 进行漏洞分析与动态 Payload 生成，需要先配置 API：

```bash
# 方式一：使用快捷命令
python vuln_cli.py /ai

# 方式二：使用中文命令
python vuln_cli.py /AI配置
```

按提示输入：
- **API_URL**: API 地址（如 `https://api.deepseek.com`）
- **API_KEY**: API 密钥
- **MODEL**: 模型名称（如 `deepseek-chat`, `gpt-4`, `gpt-3.5-turbo`）

> **提示**：DeepSeek 用户请使用官方模型名 `deepseek-chat` 或 `deepseek-reasoner`，使用不存在的模型名会导致请求超时或返回空内容。

配置文件保存在 `.config/ai_config.json`

### 3. AI 动态生成 Payload

扫描过程中，AI 会结合当前 POC 的漏洞类型和目标 URL，实时生成针对性的攻击 Payload 并立即执行测试：

```
  [AI] 生成针对性 Payload...
    │ 目标      : http://target.com
    │ POC上下文 : 当前POC: xxx - 某漏洞 (critical)
    │ 调用AI生成 Payload 中 (通常 5~30s，请耐心等待)...
    │ 请求: POST https://api.deepseek.com/chat/completions
    │ 模型: deepseek-chat (max_tokens=600)
    │ ✓ AI 响应完成，耗时 5.1s
    │ 解析: 共 3 行，识别出 3 条有效 Payload
    │   [1] POST|/upload|filename=evil.jsp&file=...|...
    │ 已保存临时文件: E:\AI-Tools\vuln_tools\.temp\ai_payload_xxx.txt
    │ 执行 Payload 测试中...
    │ [1/3] POST http://target.com/upload ✓ 命中!
```

- 生成的 Payload 保存在 `.temp/` 临时目录，扫描结束后自动清理
- 生成的临时文件供审计追溯，执行结果同样计入漏洞统计

### 4. WAF 探测与绕过

当目标部署了 WAF 时，POC 的攻击请求可能被拦截导致漏报。工具提供 WAF 探测与绕过能力。

#### 4.1 WAF 探测

```bash
python vuln_cli.py waf http://target.com
```

工具会发送 5 类无害攻击特征探针（SQL 注入 / UNION / 路径穿越 / XSS / 命令注入），与基线请求对比判断是否存在 WAF：

```
[WAF探测] 基线: HTTP 200, 309124B
[WAF探测] SQL注入(SLEEP): HTTP 423, 659B -> 拦截!
[WAF探测] 路径穿越: HTTP 423, 659B -> 拦截!
...
[!] 检测到 WAF! 类型: 自定义WAF(423封锁) 拦截状态码: 423
```

#### 4.2 绕过变体测试

探测到 WAF 后，自动测试 4 种绕过变体的有效性：

| 变体 | 原理 | 适用场景 |
|------|------|---------|
| `urlencode` | `..` → `%2e%2e`，利用 WAF 不解码编码点号的缺陷 | 路径穿越类 |
| `double` | 双重 URL 编码，利用 WAF 只解码一次的缺陷 | 通用 |
| `mixedcase` | 大小写混淆，绕过大小写敏感规则 | SQL 关键字 |
| `sqlcomment` | `--`→`/*`、空格→`/**/`，绕过基于空格的规则 | SQL 注入 |

```
  [*] 测试 WAF 绕过变体...
    urlencode    ✓ 绕过成功
    double       ✗ 仍被拦截
    ...
```

#### 4.3 扫描中自动绕过

```bash
# 扫描前探测 WAF，被拦截的请求自动尝试 4 种变形重试
python vuln_cli.py scan http://target.com --waf-detect --bypass
```

绕过成功后命中的漏洞会标注变形方式：

```
[1/78] 某路径穿越漏洞 [HIGH] ✓ 命中! (1 个发现)
    → http://target.com/portal/%2e%2e/%2e%2e/etc/passwd (HTTP 200)
    证据: root:x:0:0...
    [绕过] 通过 [urlencode] 变形绕过WAF命中!
```

### 5. Payload 挖掘模式

使用预设 Payload 对目标进行模糊测试：

```bash
# SQL 注入挖掘
python vuln_cli.py payload "http://target.com/page?id=1" --type sqli

# XSS 挖掘
python vuln_cli.py payload "http://target.com/search?q=test" --type xss

# 文件包含挖掘
python vuln_cli.py payload "http://target.com/index.php?file=test" --type lfi

# 命令注入挖掘（自定义间隔）
python vuln_cli.py payload "http://target.com/ping?host=127.0.0.1" --type cmdi --interval 1

# 使用自定义 Payload 文件
python vuln_cli.py payload "http://target.com/page?id=1" --type sqli --file ./my_payloads.txt
```

### 6. 敏感文件扫描

> ⚠️ **警告：敏感文件扫描大部分为误报，谨慎识别！！！**
>
> 1. **200 响应也可能是误报** - 某些站点的自定义 404 页面返回 HTTP 200，内容可能包含 `password`/`error` 等特征词，需人工确认页面内容是否为真实文件
> 2. **403 仅证明"路径存在或被防护拦截"** - 很多站点对任意不存在路径统一返回 403（如部分 WAF/服务器配置），不代表敏感文件真实存在
> 3. **需人工验证** - 建议对命中的路径手动访问，检查：真实文件内容 / 返回页面是否一致 / 是否有错误页特征，再决定是否报告
> 4. 综合风险等级为启发式汇总，**不可直接作为漏洞结论**，请结合业务实际判断

探测目标是否存在信息泄露的敏感文件/路径（robots.txt、.env、.git、备份文件、配置文件等 16 个常见路径）：

```bash
# 独立敏感文件扫描
python vuln_cli.py sensitive http://target.com

# 调整请求间隔（默认 1 秒）
python vuln_cli.py sensitive http://target.com --interval 0.3

# 与 POC 扫描结合（先扫敏感文件再扫 POC）
python vuln_cli.py scan http://target.com --sensitive
```

判定规则：
- **HTTP 200 + 内容特征匹配** → 确认泄露（如 `.env` 含 `APP_KEY`/`DB_PASSWORD`，`.git/HEAD` 含 `ref: refs/`，`backup.zip` 为 ZIP 魔数 `PK`）
- **HTTP 403** → 路径存在但被禁止访问（Apache 默认拒绝 `.env`/`.htaccess`/`.git`），标记 MEDIUM
- 发现漏洞用**红色字体**标注，并按 CRITICAL/HIGH/MEDIUM 汇总综合风险等级

输出示例：

```
  [*] 敏感文件扫描: http://target.com (共 16 个路径)
  ------------------------------------------------------------
  [!] 发现敏感文件: /robots.txt - robots.txt 爬虫协议(站点结构泄露) [HIGH]
      → http://target.com/robots.txt (HTTP 200, 关键字匹配: user-agent)
  [!] 发现敏感文件: /.env - .env 环境变量(密钥/数据库凭据泄露!) [MEDIUM]
      → http://target.com/.env/ (HTTP 403, 路径存在(HTTP 403 禁止访问))
  [ ] /backup.zip (HTTP 404)
  ...
============================================================
  [!] 发现 3 个敏感文件/路径, 综合风险等级: HIGH
============================================================
```

### 7. 查看 POC 列表

```bash
python vuln_cli.py list

# 指定 POC 目录
python vuln_cli.py list --pocs ./my_pocs
```

输出示例：
```
ID                                            名称                              危害
------------------------------------------------------------------------------------------
apache-log4j2-rce-CVE-2021-44228             Log4j2 JNDI 注入 RCE             CRITICAL
shiro-rememberme-deserialization             Shiro RememberMe 反序列化        HIGH
redis-unauthorized                           Redis 未授权访问                 MEDIUM
...
共 78 个 POC
```

---

## 🔧 POC 格式说明

工具完全兼容 Nuclei YAML 模板格式，支持以下特性：

### 基础结构

```yaml
id: example-vuln
info:
  name: 示例漏洞
  author: author_name
  severity: high        # critical/high/medium/low/info
  description: 漏洞描述
  tags: web,rce

http:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable/path"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "vulnerable_keyword"
        part: body
```

### 支持的变量

| 变量 | 说明 |
|------|------|
| `{{BaseURL}}` | 目标基础 URL（如 `http://target.com`） |
| `{{Hostname}}` | 目标主机名（如 `target.com`） |
| `{{randstr}}` | 随机字符串 |
| `{{rand}}` | 随机数字 |
| `{{interactsh-url}}` | OAST 外带交互域名（DNS 回连验证） |

### 匹配器类型

#### 1. Status 匹配器

```yaml
matchers:
  - type: status
    status:
      - 200
      - 301
```

#### 2. Word 匹配器

```yaml
matchers:
  - type: word
    words:
      - "error"
      - "exception"
    part: body          # body/header
```

#### 3. Regex 匹配器

```yaml
matchers:
  - type: regex
    regex:
      - "password\\s*[:=]\\s*['\"]?\\w+"
    part: body
```

#### 4. DSL 匹配器

```yaml
matchers:
  - type: dsl
    dsl:
      - 'contains(body, "admin")'
      - 'status_code == 200'
    condition: and
```

#### 5. 组合匹配（matchers-condition）

```yaml
matchers-condition: and    # and: 全部命中才算 / or: 任一命中即可
matchers:
  - type: status
    status: [200]
  - type: word
    words: ["root:x:"]
```

### Raw HTTP 请求

支持原始 HTTP 报文格式（可携带完整 Header）：

```yaml
http:
  - raw:
      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"username":"admin","password":"123456"}

    matchers:
      - type: word
        words:
          - "success"
```

### 多步骤请求

```yaml
http:
  - raw:
      - |
        GET /step1 HTTP/1.1
        Host: {{Hostname}}

      - |
        POST /step2 HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"token":"{{extracted_token}}"}

    matchers:
      - type: status
        status:
          - 200
```

---

## 📊 输出格式

### 扫描输出示例

```
============================================================
  目标: http://192.168.1.100
  POC 数量: 78
  间隔: 2s
  AI 分析: 关闭
  AI Payload: 关闭
  WAF 探测: 开启
  WAF 绕过: 开启
  敏感文件扫描: 开启
============================================================

  [WAF探测] 正在检测目标防护...
  [!] 检测到WAF: 自定义WAF(423封锁) (拦截状态码 423)
  [*] 已启用绕过模式，被拦截的请求将自动尝试变形重试

  [*] 敏感文件扫描: http://192.168.1.100 (共 16 个路径)
  [!] 发现敏感文件: /robots.txt - robots.txt 爬虫协议(站点结构泄露) [HIGH]
  ...

[1/78] Log4j2 JNDI 注入 RCE [CRITICAL] ✓ 命中! (1 个发现)   ← 红色字体
    → http://192.168.1.100/api (HTTP 200)
    证据: {"status":"success","data":"..."}

[2/78] Shiro RememberMe 反序列化 [HIGH] ✗ 未命中

...

============================================================
  扫描完成!
  总请求数: 156
  发现漏洞: 3                              ← 红色字体
  按危害级别: CRITICAL:1, HIGH:2          ← 红色字体
============================================================
```

### AI 分析输出

启用 `--ai` 参数后，工具会调用 AI 对发现的漏洞进行分析：

```
============================================================
  AI 分析中...
============================================================

根据扫描结果，发现以下漏洞：

1. [CRITICAL] Log4j2 JNDI 注入 RCE
   - 风险等级：极高
   - 利用难度：低
   - 修复建议：立即升级 Log4j 至 2.17.1+ 版本
```

---

## 🛠️ 高级功能

### 自定义 POC 目录

```bash
# 使用自定义 POC 目录
python vuln_cli.py scan http://target.com --pocs /path/to/custom/pocs

# 列出自定义目录的 POC
python vuln_cli.py list --pocs /path/to/custom/pocs
```

### 调整扫描速度

```bash
# 快速扫描（1 秒间隔）
python vuln_cli.py scan http://target.com --interval 1

# 慢速扫描（5 秒间隔，避免触发防护）
python vuln_cli.py scan http://target.com --interval 5
```

### 编码处理

工具自动处理以下编码：
- UTF-8
- GBK / GB2312 / GB18030
- CP936

检测方式：
1. HTTP Content-Type 头中的 charset
2. HTML meta 标签中的 charset
3. 内容字节流自动嗅探

---

## 📁 项目结构

```
vuln_tools/
├── vuln_cli.py              # 主程序（扫描/AI/WAF/Payload 挖掘）
├── zh.py                    # 辅助工具集（网页探活/下载/域名匹配/漏洞URL匹配）
├── requirements.txt         # 依赖清单
├── README.md                # 项目说明
├── .config/                 # 配置文件目录
│   └── ai_config.json      # AI 配置（API_URL/API_KEY/MODEL）
├── .temp/                   # AI 临时 Payload 目录（扫描后自动清理）
├── payloads/                # Payload 文件目录（sqli/xss/lfi/cmdi 等）
└── pocs/                    # POC 文件目录（默认在 E:\AI-Tools\pocs）
    ├── apache-log4j2-rce-CVE-2021-44228.yaml
    ├── shiro-rememberme-deserialization.yaml
    ├── redis-unauthorized.yaml
    └── ...
```

---

## 🔍 常见问题

### Q: 扫描很慢怎么办？

A: 使用 `--interval` 参数调整间隔：
```bash
python vuln_cli.py scan http://target.com --interval 0.5
```

### Q: AI 调用超时或卡住？

A: 检查以下几点：
1. API_URL 是否正确（DeepSeek 官方为 `https://api.deepseek.com`，末尾不要有 `/v1`）
2. API_KEY 是否有效
3. **MODEL 名称是否正确**（DeepSeek 请用 `deepseek-chat`，不存在的模型名会超时或返回空内容）
4. 网络连接是否正常
5. 工具已内置 45 秒超时和禁用自动重试，错误会快速暴露

### Q: AI 返回空内容/生成 Payload 失败？

A: 通常是模型名无效（如 reasoner 类模型思考过程耗尽 token）。请改用官方对话模型，如 `deepseek-chat`。

### Q: 扫描总是"未命中"？

A: 可能是以下原因：
1. 目标确实没有对应漏洞（POC 库覆盖的是用友/泛微/海康等特定系统）
2. **目标部署了 WAF**，攻击请求被拦截 → 用 `--waf-detect` 探测，`--bypass` 尝试绕过
3. 使用 `waf` 命令可以单独测试目标防护情况

### Q: 如何扫描敏感文件/备份文件？

A: 使用 `sensitive` 命令或 `--sensitive` 参数：
```bash
python vuln_cli.py sensitive http://target.com
python vuln_cli.py scan http://target.com --sensitive
```

### Q: 为什么控制台没有显示红色字体？

A: 工具自动启用 Windows 控制台 ANSI 彩色输出（通过 ctypes 设置 VT 模式）。若使用的终端不支持 ANSI（如旧版 cmd），请使用 Windows Terminal / PowerShell 7+ 或 `pip install colorama`。

### Q: 如何添加自定义 POC？

A: 将 YAML 文件放入 `E:\AI-Tools\pocs` 目录即可，工具会自动加载。

### Q: 扫描结果有乱码？

A: 工具已内置编码检测（GBK/GB2312/GB18030/CP936 自动转码 UTF-8），如仍有问题，请检查目标网站的实际编码。

### Q: 支持 HTTPS 吗？

A: 支持，工具会自动处理 SSL 证书验证并忽略自签名证书警告。

---

## ⚠️ 免责声明

**重要提醒**：

1. **合法授权** - 本工具仅供安全研究和授权测试使用，未经授权对目标进行扫描属于违法行为
2. **责任自负** - 使用本工具产生的任何法律后果由使用者自行承担
3. **道德使用** - 请勿将本工具用于非法用途
4. **风险提示** - 大量扫描可能对目标造成压力，请在生产环境谨慎使用
5. **WAF 绕过提示** - 绕过防护进行未授权测试同样违法，仅限授权范围内使用

**All operations must ensure legal authorization for the target. The above PoC is for authorized verification only. Unauthorized execution is illegal.**

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

### 贡献 POC

请确保 POC 符合以下规范：
- 使用标准 Nuclei YAML 格式
- 包含完整的 `info` 字段
- 提供准确的 `severity` 级别
- 经过实际测试验证

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

---

## 🙏 致谢

- [Nuclei](https://github.com/projectdiscovery/nuclei) - 优秀的漏洞扫描框架
- [ProjectDiscovery](https://github.com/projectdiscovery) - 安全工具开发团队

---

## 📮 联系方式

如有问题或建议，请通过 GitHub Issues 反馈。

---

<div align="center">

**⭐ 如果这个项目对你有帮助，请给个 Star 支持一下！⭐**

</div>
