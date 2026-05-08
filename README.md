# AutoAIO Security Test Platform — 自动化安全测试平台

针对物联网（IoT）智能家居设备的模块化安全测试平台，用于效率化地执行 TLS 证书画像分析、域名劫持测试、网络端口扫描和固件漏洞扫描。

**版本：v2.0.0**

---

## 功能模块

| 模块 | 说明 |
|------|------|
| **TLS 域名分析** | 从 Wireshark 抓取的 pcap/pcapng 流量包中提取 TLS SNI 域名及 HTTP 明文 URL；连接目标服务器获取真实证书画像（密钥类型/位数/曲线/SAN/KeyUsage/EKU/BasicConstraints），自动生成匹配的自签名证书用于域名劫持测试 |
| **网络扫描** | 调用本机 nmap 对目标执行 TCP/UDP 端口扫描（精简/详细两种策略），输出文本/XML 报告 |
| **漏洞扫描** | 集成 cve-bin-tool，扫描 IoT 固件及二进制文件中的已知 CVE 漏洞，支持 CVSS 过滤和多种报告格式 |

---

## 用户本机环境要求

以下软件**无法**随 PyInstaller 打包进 exe，每位使用者需要在自己的电脑上预先安装：

### 1. Python 3.8+

- 下载：[https://www.python.org/downloads/](https://www.python.org/downloads/)
- 安装时勾选 "Add Python to PATH"

### 2. Wireshark / TShark（TLS 分析模块依赖）

- 下载：[https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)
- 安装时必须勾选 **"Install TShark"** 组件
- 安装后将 Wireshark 目录添加到系统 PATH，或在使用时通过 `--tshark-path` 指定 tshark.exe 路径
- 验证安装：`tshark --version`

### 3. Nmap（网络扫描模块依赖）

- 下载：[https://nmap.org/download.html](https://nmap.org/download.html)
- 安装时勾选 "Add Nmap to the system PATH"
- 验证安装：`nmap --version`

### 4. OpenSSL（TLS 证书生成依赖）

- Windows：推荐使用 [Win64 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) 或 Git for Windows 自带的 OpenSSL
- Linux：`sudo apt install openssl`
- macOS：`brew install openssl`
- 验证安装：`openssl version`

### 5. cve-bin-tool（漏洞扫描模块依赖）

- 源码运行时已包含在 `requirement.txt` 的 Python 依赖中，通过 pip 自动安装
- 打包版 exe 不内置系统级 `cve-bin-tool` 环境；漏洞扫描模块会按以下顺序查找：
  - GUI/CLI 手动指定的 cve-bin-tool 路径
  - 环境变量 `AUTOAIO_CVE_BIN_TOOL`
  - 程序目录下的独立 `tools/cve-bin-tool.exe`
  - 程序目录下的 `tools/cve-venv` 或 `tools/.venv` 专用工具环境
  - 系统 `PATH` 中的 `cve-bin-tool`
- 推荐给测试同事准备一个专用工具虚拟环境，安装后在 GUI 中选择 `.venv\Scripts\cve-bin-tool.exe` 或 `.venv\Scripts\python.exe`
- 注意：不要只复制虚拟环境里的 `cve-bin-tool.exe` 单文件，它依赖同一个虚拟环境中的 Python 包
- 首次运行时会自动下载 NVD 漏洞数据库（约数百 MB），需保持网络通畅
- 建议申请 [NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) 以提升 API 限速（免费注册，即时获取）
- 验证安装：`cve-bin-tool --version`

Windows 专用工具环境示例：

```powershell
python -m venv C:\AutoAIO-Tools\cve-venv
C:\AutoAIO-Tools\cve-venv\Scripts\python.exe -m pip install cve-bin-tool==3.4
C:\AutoAIO-Tools\cve-venv\Scripts\cve-bin-tool.exe --version
```

---

## 安装（开发者）

```bash
# 1. 克隆或复制项目到本地
cd Auto_AIO_DS

# 2. 创建并激活虚拟环境（推荐）
python -m venv .venv

# Windows
.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate

# 3. 安装 Python 依赖
pip install -r requirement.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

> **注意**：cve-bin-tool 首次运行时会自动下载 NVD 漏洞数据库（数百 MB），请耐心等待。如需加速可申请 [NVD API Key](https://nvd.nist.gov/developers/request-an-api-key)。

---

## 使用方法

### GUI 图形界面（推荐）

```bash
python gui.py
```

界面分为三个标签页：
- **TLS 域名分析** — 选择 pcap 文件 → 可选配 TShark 路径和输出目录 → 勾选"生成证书" → 点击执行
- **网络扫描** — 输入目标 IP → 选择 TCP/UDP → 精简/详细模式 → 执行
- **漏洞扫描** — 选择固件目录或二进制文件 → 配置报告格式/CVSS 阈值/API Key → 执行

实时日志在底部区域显示，所有输出文件自动生成到带时间戳的项目目录。

### CLI 命令行

#### TLS 域名分析

```bash
# 基本分析
python test.py tls capture.pcapng

# 指定 TShark 路径
python test.py tls capture.pcapng --tshark-path "C:\Program Files\Wireshark\tshark.exe"

# 分析并生成自签名证书
python test.py tls capture.pcapng --generate-certificates

# 指定输出目录
python test.py tls capture.pcapng --output-dir ./analysis_output

# 调试模式（输出详细日志）
python test.py --debug tls capture.pcapng
```

#### 网络扫描

```bash
# TCP 详细扫描（全端口 + OS检测 + 服务版本）
python test.py network 192.168.1.1

# TCP 精简扫描（仅端口 + 服务版本，速度快）
python test.py network 192.168.1.1 --lite

# UDP 服务扫描
python test.py network 192.168.1.1 --scan-mode udp

# 输出 XML 报告
python test.py network 192.168.1.1 --xml-output

# 指定输出目录
python test.py network 192.168.1.1 --output-dir ./scan_output
```

#### 漏洞扫描（固件 CVE）

```bash
# 基本扫描（CSV 报告）
python test.py vuln ./firmware_extracted/

# JSON 格式 + 仅高危以上 + CVSS >= 7.0
python test.py vuln ./firmware_extracted/ --format json --severity high --cvss 7.0

# 立即更新漏洞库 + 使用 NVD API Key
python test.py vuln ./firmware_extracted/ --update-db now --nvd-api-key xxxxx-xxxxx

# 离线模式（不联网，使用已有缓存数据库）
python test.py vuln ./firmware_extracted/ --offline

# HTML 可视化报告
python test.py vuln ./firmware_extracted/ --format html

# 显式指定 cve-bin-tool 路径
python test.py vuln ./firmware_extracted/ --cve-bin-tool C:\AutoAIO-Tools\cve-venv\Scripts\cve-bin-tool.exe

# 也可以指定专用工具虚拟环境里的 Python
python test.py vuln ./firmware_extracted/ --cve-bin-tool C:\AutoAIO-Tools\cve-venv\Scripts\python.exe
```

#### 通用选项

```bash
python test.py --version      # 查看版本
python test.py --help          # 查看帮助
python test.py tls --help      # 查看 TLS 模块帮助
python test.py vuln --help     # 查看漏洞扫描模块帮助
```

---

## 输出目录结构

每次分析会自动创建带时间戳的项目目录：

```
security_test_2026-05-08_14-30-22/
│
├── example.com/                  # 每个域名一个子目录
│   ├── server.crt                #   自签名证书
│   ├── server.csr                #   证书签名请求
│   └── server.key                #   私钥
│
├── ota.io.mi.com/
│   ├── server.crt
│   ├── server.csr
│   └── server.key
│
├── non_domain_sni/               # 非域名 SNI 标识（如随机字符串）
│   └── non_domain_sni_20260508_143022.txt
│
├── http/                         # HTTP 明文 URL
│   └── http_urls_20260508_143022.txt
│
├── vuln_scan_firmware_20260508_143022/   # CVE 扫描结果
│   ├── cve_report_20260508_143022.csv
│   └── scan_summary_20260508_143022.txt
│
└── nmap_lite_tcp_scan_192_168_1_1/      # Nmap 扫描结果
    ├── nmap_lite_tcp_scan_192.168.1.1.txt
    └── nmap_lite_tcp_scan_192.168.1.1.xml
```

日志文件位于项目根目录 `logs/` 下：
```
logs/
├── tls_analyzer_20260508_143022.log
├── network_scanner_20260508_143035.log
└── vulnerability_scanner_20260508_143050.log
```

---

## 打包分发（PyInstaller → exe）

将工具打包成单个 exe 文件分发给团队成员，对方**无需安装 Python 或任何 pip 包**（但仍需安装 Wireshark、nmap、OpenSSL 三项系统软件）。

### 一键打包（Windows）

```bash
build_gui.bat
```

脚本自动执行 4 步：(1) 检查 Python → (2) 创建/激活 venv → (3) 安装依赖 → (4) PyInstaller 打包。

打包完成后输出文件：
```
dist/AutoAIO_Security_Test.exe
```

### 手动打包

```bash
pip install pyinstaller pyinstaller-hooks-contrib
pyinstaller AutoAIO_Security_Test.spec --noconfirm
```

### 分发给同事

将以下内容打包成 zip 发给每位使用者：

1. **`dist/AutoAIO_Security_Test.exe`** — 主程序
2. **一份系统要求说明** — 告知对方需预装 Wireshark、nmap、OpenSSL（见上文"用户本机环境要求"）
3. 对方双击 exe 即可使用，无需 Python 环境

> **注意**：PyInstaller 打包的 exe 启动速度取决于杀毒软件扫描速度，首次启动可能需要 10-30 秒。

---

## 跨平台支持

本平台设计为跨平台，可在 Windows、Linux 和 macOS 上运行。不同平台需对应安装各自的系统软件（Wireshark/tshark、nmap、OpenSSL）。

---

## 扩展

平台采用模块化架构（`core.py` 的 `BaseModule` + `ModuleManager`），新增功能只需：
1. 创建继承 `BaseModule` 的类
2. 实现 `name()`、`description()`、`execute(params)` 三个方法
3. 在 `ModuleManager` 中注册即可被 CLI 和 GUI 同时使用
