# aivuln CLI - Python 版漏洞扫描工具

<div align="center">

**基于 Nuclei YAML 模板的自动化漏洞检测工具**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![POC Count](https://img.shields.io/badge/POCs-90+-orange.svg)](pocs/)

</div>

---

## 📖 项目简介

aivuln CLI 是一个基于 Python 的自动化漏洞扫描工具，完全兼容 **Nuclei YAML 模板格式**。工具采用模块化设计，支持批量 POC 执行、智能匹配、AI 辅助分析等功能。

### ✨ 核心特性

- 🎯 **Nuclei 兼容** - 完全支持 Nuclei YAML POC 格式
- 🔄 **批量扫描** - 自动加载并执行多个 POC，按危害级别排序
- 🤖 **AI 分析** - 集成 AI 辅助漏洞分析（支持 OpenAI 兼容 API）
- 🌐 **编码自适应** - 自动检测 GBK/GB2312 编码，解决中文乱码问题
- ⚡ **灵活配置** - 支持自定义 POC 目录、执行间隔、HTTP 超时等
- 📊 **结构化输出** - 清晰的扫描结果展示，包含证据和状态码

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
# 指定 POC 目录
python vuln_cli.py scan http://target.com --pocs ./my_pocs

# 调整执行间隔（默认 2 秒）
python vuln_cli.py scan http://target.com --interval 1

# 启用 AI 分析
python vuln_cli.py scan http://target.com --ai

# 组合使用
python vuln_cli.py scan http://target.com --pocs ./custom_pocs --interval 1 --ai
```

### 2. 配置 AI 分析

工具支持集成 AI 进行漏洞分析，需要先配置 API：

```bash
# 方式一：使用快捷命令
python vuln_cli.py /ai

# 方式二：使用中文命令
python vuln_cli.py /AI配置
```

按提示输入：
- **API_URL**: API 地址（如 `https://api.openai.com/v1`）
- **API_KEY**: API 密钥
- **MODEL**: 模型名称（如 `gpt-4`, `gpt-3.5-turbo`）

配置文件保存在 `.config/ai_config.json`

### 3. 查看 POC 列表

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
共 93 个 POC
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
    path: "{{BaseURL}}/vulnerable/path"
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
    condition: and      # and/or
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

### Raw HTTP 请求

支持原始 HTTP 报文格式：

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
  POC 数量: 93
  间隔: 2s
  AI 分析: 关闭
============================================================

[1/93] Log4j2 JNDI 注入 RCE [CRITICAL] ✓ 命中! (1 个发现)
    → http://192.168.1.100/api (HTTP 200)
    证据: {"status":"success","data":"..."}

[2/93] Shiro RememberMe 反序列化 [HIGH] ✗ 未命中

...

============================================================
  扫描完成!
  总请求数: 186
  发现漏洞: 3
  按危害级别: CRITICAL:1, HIGH:2
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

2. [HIGH] Shiro RememberMe 反序列化
   - 风险等级：高
   - 利用难度：中
   - 修复建议：升级 Shiro 至 1.8.0+ 并更换默认密钥

...
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

---

## 📁 项目结构

```
vuln_tools/
├── vuln_cli.py              # 主程序
├── requirements.txt         # 依赖清单
├── README.md               # 项目说明
├── .config/                # 配置文件目录
│   └── ai_config.json      # AI 配置
└── pocs/                   # POC 文件目录
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

### Q: AI 分析报错？

A: 检查以下几点：
1. API_URL 是否正确（末尾不要有 `/`）
2. API_KEY 是否有效
3. MODEL 名称是否正确
4. 网络连接是否正常

### Q: 如何添加自定义 POC？

A: 将 YAML 文件放入 `pocs/` 目录即可，工具会自动加载。

### Q: 扫描结果有乱码？

A: 工具已内置编码检测，如仍有问题，请检查目标网站的实际编码。

### Q: 支持 HTTPS 吗？

A: 支持，工具会自动处理 SSL 证书验证。

---

## ⚠️ 免责声明

**重要提醒**：

1. **合法授权** - 本工具仅供安全研究和授权测试使用，未经授权对目标进行扫描属于违法行为
2. **责任自负** - 使用本工具产生的任何法律后果由使用者自行承担
3. **道德使用** - 请勿将本工具用于非法用途
4. **风险提示** - 大量扫描可能对目标造成压力，请在生产环境谨慎使用

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
