# 自动化安全测试平台

这是一个模块化的自动化安全测试平台，专门用于对带有WIFI、蓝牙或4G模块的智能家居设备进行安全测试。

## 功能

- 分析网络抓包文件(.pcapng)，提取TLS握手过程中的域名信息
- 使用nmap对目标设备进行全端口扫描
- 自动生成按时间戳命名的项目目录
- 根据提取的域名创建分类目录，便于后续分析
- 记录详细的操作日志

## 安装依赖

```bash
pip install -r requirements.txt
```

注意：
1. 使用pyshark库需要安装Wireshark或tshark
2. 使用网络扫描模块需要安装nmap

## 使用方法

### 命令行版本 (原有功能)

#### TLS域名分析
```bash
python test.py tls capture.pcapng
```

#### 网络扫描
```bash
python test.py network 192.168.1.1
python test.py network 192.168.1.1 --xml-output    # 同时生成XML格式报告
```

#### 查看版本信息
```bash
python test.py --version
```

#### 查看帮助信息
```bash
python test.py --help
```

#### 调试模式
```bash
python test.py --debug network 192.168.1.1         # 调试模式，显示详细日志
```

#### 指定输出目录
```bash
python test.py tls capture.pcapng --output-dir ./analysis_output
python test.py network 192.168.1.1 --output-dir ./scan_output
```

### GUI版本 (推荐给团队使用)

**开箱即用的桌面应用！**

1. **获取可执行文件**: 联系项目维护者获取 `dist/AutoAIO_Security_Test.exe` 文件
2. **直接运行**: 双击exe文件即可启动图形界面
3. **无需安装**: 包含所有依赖，无需安装Python或其他组件
4. **简单易用**: 
   - 拖拽pcap文件到输入框
   - 输入目标IP地址
   - 点击执行按钮
   - 查看实时日志和结果

### 开发者：打包GUI版本

如果你需要自己打包GUI版本分发给同事：

```bash
# Windows系统
build_gui.bat

# 打包完成后，将dist目录下的所有文件分发给同事即可
```

例如：
```bash
python test.py tls capture.pcapng
python test.py network 192.168.1.1
python test.py network 192.168.1.1 --xml-output
```

## 输出格式

### TLS分析结果
程序会在指定目录下创建如下格式的目录结构：
```
security_test_<timestamp>/
├── <domain1>/
├── <domain2>/
├── <domain3>/
...
```

### Nmap扫描结果
网络扫描结果会创建如下格式的目录结构：
```
nmap_scan_<target_ip>/
└── nmap_scan/
    ├── nmap_scan_<target_ip>.txt    # 文本格式扫描结果（默认）
    └── nmap_scan_<target_ip>.xml    # XML格式扫描结果（可选，使用--xml-output参数）
```

### 日志文件
每次执行都会生成日志文件，位于 `logs/` 目录下，文件名格式为 `<模块名>_<时间戳>.log`:
```
logs/
├── tls_analyzer_20260309_091523.log
├── network_scanner_20260309_091634.log
└── vulnerability_scanner_20260309_091745.log
```

其中timestamp是当前日期时间，格式为 `YYYYMMDD_HHMMSS`。

## 关于J文件的说明

如果你在运行过程中产生了名为`J`的文件，这通常是由于在早期版本中命令行参数处理不当导致的。更新后的代码已经解决了这个问题。

## 跨平台支持

本平台设计为跨平台，可在Windows、Linux和macOS系统上运行。

## 扩展

此平台设计为模块化，可以继续添加更多安全测试功能。