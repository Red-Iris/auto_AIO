# AutoAIO Security Test Platform — 自动化安全测试平台

针对物联网（IoT）智能家居设备的模块化安全测试平台，用于效率化地执行 TLS 证书画像分析、域名劫持测试、网络端口扫描和固件漏洞扫描。

**版本：v2.1.0**

---

## 10分钟开箱即用（新设备首次配置）

### 1. 安装系统软件

以下三个工具需要手动安装（一次性操作）：

| 工具 | 下载 | 注意 |
|------|------|------|
| **Wireshark** | https://www.wireshark.org/download.html | 安装时勾选 "Install TShark" |
| **Nmap** | https://nmap.org/download.html | 安装时勾选 "Add Nmap to the system PATH" |
| **OpenSSL** | https://slproweb.com/products/Win32OpenSSL.html | 选 Win64 OpenSSL 版本 |

> Linux 用户：`sudo apt install tshark nmap openssl`  
> macOS 用户：`brew install wireshark nmap openssl`

### 2. 一键环境检测 + cve-bin-tool 安装

```powershell
# Windows（在项目目录下执行）
.\setup.ps1
```

```bash
# Linux / macOS
chmod +x setup.sh && ./setup.sh
```

脚本自动完成：
- 检测 Python、TShark、Nmap、OpenSSL 是否就绪
- 给出缺失工具的下载链接
- 在 `tools/cve-venv/` 下创建独立的 cve-bin-tool 虚拟环境（清华镜像源）
- 生成 `config.json` 保存检测到的工具路径

启动 GUI 后切到"系统检查"标签页可随时复查环境状态。首次启动时会自动将发现的工具路径写入 `config.json`。

---

## 功能模块

| 模块 | 说明 |
|------|------|
| **TLS 域名分析** | 从 Wireshark 抓取的 pcap/pcapng 流量包中提取 TLS SNI 域名及 HTTP 明文 URL；连接目标服务器获取真实证书画像（密钥类型/位数/曲线/SAN/KeyUsage/EKU/BasicConstraints），自动生成匹配的自签名证书用于域名劫持测试 |
| **网络扫描** | 调用本机 nmap 对目标执行 TCP/UDP 端口扫描（精简/详细两种策略），输出文本/XML 报告 |
| **漏洞扫描** | 集成 cve-bin-tool，扫描 IoT 固件及二进制文件中的已知 CVE 漏洞，支持 CVSS 过滤和多种报告格式 |

---

## 使用方法

### GUI 图形界面（推荐）

```bash
python gui.py
```

界面采用侧边栏导航 + 深浅色双主题设计：

- **侧边栏** — 四个功能模块一键切换，底部滑动开关一键切换深色/浅色主题
- **TLS 域名分析** — 选择 pcap 文件 → 可选配 TShark 路径和输出目录 → 勾选"生成证书" → 点击执行
- **网络扫描** — 输入目标 IP → 选择 TCP/UDP → 精简/详细模式 → 执行
- **漏洞扫描** — 选择固件目录或二进制文件 → 配置报告格式/CVSS 阈值/API Key → 执行
- **系统检查** — 一键检测本机环境是否就绪，显示各工具版本和路径
- **执行日志** — 底部日志面板可通过拖拽分割条自由调整大小，支持折叠/展开
- **主题切换** — 侧边栏底部的滑动开关一键切换深色/浅色主题，设置自动持久化

首次启动自动检测 TShark 路径并保存到 `config.json`，后续启动自动回填。

### CLI 命令行

#### TLS 域名分析

```bash
python test.py tls capture.pcapng
python test.py tls capture.pcapng --generate-certificates
python test.py tls capture.pcapng --tshark-path "C:\Program Files\Wireshark\tshark.exe"
python test.py tls capture.pcapng --output-dir ./analysis_output
```

#### 网络扫描

```bash
python test.py network 192.168.1.1
python test.py network 192.168.1.1 --xml-output
```

#### 漏洞扫描

```bash
python test.py vuln ./firmware_extracted/
python test.py vuln ./firmware_extracted/ --format json --severity high --cvss 7.0
python test.py vuln ./firmware_extracted/ --offline
python test.py vuln ./firmware_extracted/ --nvd-api-key xxxxx-xxxxx
```

#### 通用选项

```bash
python test.py --version
python test.py --help
python test.py --debug tls capture.pcapng    # 调试模式
```

---

## 安装（开发者）

```bash
cd Auto_AIO_DS

# 创建虚拟环境
python -m venv .venv

# Windows
.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate

# 安装依赖（清华镜像优先，失败自动回退 PyPI 官方源）
pip install -r requirement.txt

# 运行
python gui.py
```

> 技术栈：Python 3.8+ / PyQt6 / pyshark / python-nmap / OpenSSL / cve-bin-tool

---

## 打包分发（PyInstaller → exe）

```bash
build_gui.bat
```

输出：`dist/AutoAIO_Security_Test.exe`

### 使用方法

1. `dist/AutoAIO_Security_Test.exe` — 主程序（无需 Python）
2. `style_dark.qss` / `style_light.qss` — 主题样式文件（与 exe 同目录）
3. `setup.ps1` / `setup.sh` — 环境检测脚本
4. 先运行 `setup.ps1`，再双击 exe

> 注意：exe 仍需 Wireshark、Nmap、OpenSSL 三项系统软件。cve-bin-tool 由 setup 脚本自动安装到 `tools/` 目录。

---

## 配置系统

`config.json`（程序目录下，首次启动自动生成）保存以下设置：

| 配置项 | 说明 |
|--------|------|
| `tshark_path` | TShark 可执行文件路径 |
| `cve_bin_tool_path` | cve-bin-tool 路径 |
| `nvd_api_key` | NVD API 密钥 |
| `default_output_dir` | 默认输出目录 |
| `theme` | 界面主题（dark / light） |

查找优先级：**命令行参数 > config.json > 自动发现（PATH / 常见路径）**

---

## 输出目录结构

```
security_test_2026-05-08_14-30-22/
├── example.com/
│   ├── server.crt / server.csr / server.key
├── non_domain_sni/
│   └── non_domain_sni_20260508_143022.txt
├── http/
│   └── http_urls_20260508_143022.txt
├── vuln_scan_firmware_20260508_143022/
│   ├── cve_report_20260508_143022.csv
│   ├── scan_summary_20260508_143022.txt
│   └── cve_raw_output_20260508_143022.log
└── nmap_tcp_scan_192_168_1_1/
    ├── nmap_tcp_scan_192.168.1.1.txt
    └── nmap_tcp_scan_192.168.1.1.xml
```

日志文件位于 `logs/`（自动清理 30 天前的旧日志）。

---

## cve-bin-tool 发现策略

漏洞扫描模块按以下顺序查找 cve-bin-tool：

1. GUI/CLI 手动指定的路径
2. 环境变量 `AUTOAIO_CVE_BIN_TOOL`
3. 程序目录 `tools/cve-venv/` 下的专用工具环境（setup 脚本创建）
4. 程序目录 `tools/` 下的独立 exe
5. 系统 PATH 中的 `cve-bin-tool`
6. 当前 Python 环境中的 `cve-bin-tool` 脚本入口
7. （源码运行时）`python -m cve_bin_tool.cli`

> 推荐做法：运行 `setup.ps1` 自动在 `tools/cve-venv/` 创建隔离环境，GUI 会自动发现。

---

## 跨平台支持

本平台支持 Windows、Linux 和 macOS。TShark 路径发现策略：

1. 优先通过系统 PATH 查找（`shutil.which`）
2. 回退到各平台常见安装路径
3. 用户可通过配置文件或命令行参数显式指定

不同平台需对应安装各自的系统软件版本。

---

## 扩展

平台采用模块化架构（`core.py` 的 `BaseModule` + `ModuleManager`），新增功能只需：

1. 创建继承 `BaseModule` 的类
2. 实现 `name()`、`description()`、`execute(params)` 三个方法
3. 在 CLI/GUI 中注册即可使用
