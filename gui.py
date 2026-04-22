#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自动化安全测试平台 - GUI版本

Author: Reid Xu
Date: 2026-03-10
"""

import sys
import os
import asyncio
import logging
from pathlib import Path
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QFileDialog,
    QTabWidget, QGroupBox, QCheckBox, QMessageBox, QProgressBar,
    QTreeWidget, QTreeWidgetItem, QSplitter, QStatusBar, QRadioButton
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QThread
from PyQt5.QtGui import QFont, QIcon

# 导入现有模块
from core import ModuleManager, get_default_tshark_path
from modules import TLSAnalyzerModule, NetworkScannerModule, VulnerabilityScannerModule


class WorkerSignals(QObject):
    """工作线程信号"""
    finished = pyqtSignal(bool, str)
    progress = pyqtSignal(str)
    log_message = pyqtSignal(str)


class QtLogHandler(logging.Handler):

    def __init__(self, signals):
        super().__init__()
        self.signals = signals

    def emit(self, record):
        try:
            self.signals.log_message.emit(self.format(record))
        except Exception:
            self.handleError(record)


class WorkerThread(QThread):
    """后台工作线程"""
    def __init__(self, module_manager, module_name, params):
        super().__init__()
        self.module_manager = module_manager
        self.module_name = module_name
        self.params = params
        self.signals = WorkerSignals()

    def run(self):
        loop = None
        original_print = None
        gui_log_handler = None
        module_logger = None
        
        try:
            # 设置asyncio事件循环（解决pyshark在子线程中的事件循环问题）
            if sys.platform == 'win32':
                # 尝试使用ProactorEventLoop而不是SelectorEventLoop
                loop = asyncio.ProactorEventLoop()
            else:
                loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # 重定向print输出到日志
            original_print = print
            def custom_print(*args, **kwargs):
                message = ' '.join(str(arg) for arg in args)
                self.signals.log_message.emit(message)
                original_print(*args, **kwargs)
                # 不调用original_print以避免控制台输出
            
            # 实际替换print函数
            import builtins
            builtins.print = custom_print
            
            module = self.module_manager.modules.get(self.module_name)
            module_logger = getattr(module, 'logger', None)
            if module_logger:
                gui_log_handler = QtLogHandler(self.signals)
                gui_log_handler.setLevel(logging.WARNING)
                gui_log_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                ))
                module_logger.addHandler(gui_log_handler)
            
            # 执行模块
            success = self.module_manager.execute_module(self.module_name, self.params)
            result_msg = "执行成功" if success else "执行失败"
            self.signals.finished.emit(success, result_msg)
            
            # 清理事件循环
            loop.close()
            
        except Exception as e:
            self.signals.log_message.emit(f"执行过程中发生错误: {str(e)}")
            self.signals.finished.emit(False, f"执行失败: {str(e)}")
            # 确保事件循环被清理
            try:
                if loop:
                    loop.close()
            except:
                pass
            
        finally:
            if module_logger and gui_log_handler:
                module_logger.removeHandler(gui_log_handler)
                gui_log_handler.close()

            # 恢复原始print函数
            if original_print is not None:
                import builtins
                builtins.print = original_print


class SecurityTestGUI(QMainWindow):
    """安全测试平台GUI主窗口"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("自动化安全测试平台 v1.1.0")
        self.setGeometry(100, 100, 1200, 800)
        
        # 初始化模块管理器
        self.module_manager = ModuleManager()
        self.module_manager.register_module(TLSAnalyzerModule(debug_mode=True))
        self.module_manager.register_module(NetworkScannerModule(debug_mode=True))
        self.module_manager.register_module(VulnerabilityScannerModule(debug_mode=True))
        
        self.current_worker = None
        
        self.init_ui()
        
    def init_ui(self):
        """初始化用户界面"""
        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 创建标签页
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # TLS分析标签页
        tls_tab = self.create_tls_tab()
        self.tab_widget.addTab(tls_tab, "TLS域名分析")
        
        # 网络扫描标签页
        network_tab = self.create_network_tab()
        self.tab_widget.addTab(network_tab, "网络扫描")
        
        # 漏洞扫描标签页（预留）
        vuln_tab = self.create_vuln_tab()
        self.tab_widget.addTab(vuln_tab, "漏洞扫描")
        
        # 日志显示区域
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Consolas", 10))
        main_layout.addWidget(QLabel("执行日志:"))
        main_layout.addWidget(self.log_display)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # 状态栏
        self.statusBar().showMessage("就绪")
        
    def create_tls_tab(self):
        """创建TLS分析标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 文件选择组
        file_group = QGroupBox("PCAP文件")
        file_layout = QHBoxLayout()
        
        self.tls_file_input = QLineEdit()
        self.tls_file_input.setPlaceholderText("请拖拽.pcapng文件或点击浏览按钮")
        self.tls_file_input.setAcceptDrops(True)
        
        browse_btn = QPushButton("浏览...")
        browse_btn.clicked.connect(self.browse_tls_file)
        
        file_layout.addWidget(self.tls_file_input)
        file_layout.addWidget(browse_btn)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # TShark路径组
        tshark_group = QGroupBox("TShark路径 (可选)")
        tshark_layout = QHBoxLayout()
        
        self.tshark_path_input = QLineEdit()
        default_tshark = get_default_tshark_path()
        if default_tshark:
            self.tshark_path_input.setText(default_tshark)
        else:
            self.tshark_path_input.setPlaceholderText("自动检测或手动指定TShark路径")
            
        tshark_browse_btn = QPushButton("浏览...")
        tshark_browse_btn.clicked.connect(self.browse_tshark_path)
        
        tshark_layout.addWidget(self.tshark_path_input)
        tshark_layout.addWidget(tshark_browse_btn)
        tshark_group.setLayout(tshark_layout)
        layout.addWidget(tshark_group)
        
        # 输出目录组
        output_group = QGroupBox("输出目录 (可选)")
        output_layout = QHBoxLayout()
        
        self.tls_output_input = QLineEdit()
        self.tls_output_input.setPlaceholderText("默认为当前目录")
        
        output_browse_btn = QPushButton("浏览...")
        output_browse_btn.clicked.connect(self.browse_output_dir)
        
        output_layout.addWidget(self.tls_output_input)
        output_layout.addWidget(output_browse_btn)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # 证书生成选项组
        cert_group = QGroupBox("证书生成选项 (可选)")
        cert_layout = QHBoxLayout()
        
        self.generate_cert_checkbox = QCheckBox("为每个域名生成证书、密钥和自签名文件")
        cert_layout.addWidget(self.generate_cert_checkbox)
        cert_group.setLayout(cert_layout)
        layout.addWidget(cert_group)
        
        # 执行按钮
        execute_btn = QPushButton("开始TLS分析")
        execute_btn.clicked.connect(self.execute_tls_analysis)
        execute_btn.setStyleSheet("background-color: #4CAF50; color: white; font-size: 14px;")
        layout.addWidget(execute_btn)
        
        return tab
        
    def create_network_tab(self):
        """创建网络扫描标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 目标IP组
        ip_group = QGroupBox("目标IP地址")
        ip_layout = QHBoxLayout()
        
        self.target_ip_input = QLineEdit()
        self.target_ip_input.setPlaceholderText("例如: 192.168.1.1")
        
        ip_layout.addWidget(QLabel("IP地址:"))
        ip_layout.addWidget(self.target_ip_input)
        ip_group.setLayout(ip_layout)
        layout.addWidget(ip_group)
        
        # 选项组
        options_group = QGroupBox("扫描选项")
        options_layout = QVBoxLayout()
        
        # 扫描模式选择
        scan_mode_layout = QHBoxLayout()
        self.tcp_radio = QRadioButton("TCP扫描")
        self.udp_radio = QRadioButton("UDP扫描")
        self.tcp_radio.setChecked(True)  # 默认选择TCP模式
        
        scan_mode_layout.addWidget(self.tcp_radio)
        scan_mode_layout.addWidget(self.udp_radio)
        options_layout.addLayout(scan_mode_layout)
        
        # 精简模式选项
        self.lite_mode_checkbox = QCheckBox("使用精简模式（适合快速展示）")
        options_layout.addWidget(self.lite_mode_checkbox)
        
        self.xml_output_checkbox = QCheckBox("生成XML格式报告")
        options_layout.addWidget(self.xml_output_checkbox)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # 输出目录组
        output_group = QGroupBox("输出目录 (可选)")
        output_layout = QHBoxLayout()
        
        self.network_output_input = QLineEdit()
        self.network_output_input.setPlaceholderText("默认为当前目录")
        
        output_browse_btn = QPushButton("浏览...")
        output_browse_btn.clicked.connect(lambda: self.browse_output_dir_network())
        
        output_layout.addWidget(self.network_output_input)
        output_layout.addWidget(output_browse_btn)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # 执行按钮
        execute_btn = QPushButton("开始网络扫描")
        execute_btn.clicked.connect(self.execute_network_scan)
        execute_btn.setStyleSheet("background-color: #2196F3; color: white; font-size: 14px;")
        layout.addWidget(execute_btn)
        
        return tab
        
    def create_vuln_tab(self):
        """创建漏洞扫描标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        label = QLabel("漏洞扫描模块正在开发中...")
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("font-size: 16px; color: gray;")
        layout.addWidget(label)
        
        return tab
        
    def browse_tls_file(self):
        """浏览TLS文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择PCAP文件", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if file_path:
            self.tls_file_input.setText(file_path)
            
    def browse_tshark_path(self):
        """浏览TShark路径"""
        if sys.platform == "win32":
            file_path, _ = QFileDialog.getOpenFileName(
                self, "选择TShark可执行文件", "", "Executable Files (*.exe);;All Files (*)"
            )
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "选择TShark可执行文件", "/usr/bin", "All Files (*)"
            )
        if file_path:
            self.tshark_path_input.setText(file_path)
            
    def browse_output_dir(self):
        """浏览输出目录"""
        dir_path = QFileDialog.getExistingDirectory(self, "选择输出目录")
        if dir_path:
            self.tls_output_input.setText(dir_path)
            
    def browse_output_dir_network(self):
        """浏览网络扫描输出目录"""
        dir_path = QFileDialog.getExistingDirectory(self, "选择输出目录")
        if dir_path:
            self.network_output_input.setText(dir_path)
            
    def execute_tls_analysis(self):
        """执行TLS分析"""
        pcap_file = self.tls_file_input.text().strip()
        if not pcap_file:
            QMessageBox.warning(self, "输入错误", "请选择PCAP文件")
            return
            
        if not os.path.exists(pcap_file):
            QMessageBox.warning(self, "文件错误", "指定的PCAP文件不存在")
            return
            
        # 准备参数
        params = {'pcap_file': pcap_file}
        
        tshark_path = self.tshark_path_input.text().strip()
        if tshark_path and os.path.exists(tshark_path):
            params['tshark_path'] = tshark_path
            
        output_dir = self.tls_output_input.text().strip()
        if output_dir:
            params['output_dir'] = output_dir
            
        # 添加证书生成参数
        params['generate_certificates'] = self.generate_cert_checkbox.isChecked()
            
        self.start_worker('tls_analyzer', params)
        
    def execute_network_scan(self):
        """执行网络扫描"""
        target_ip = self.target_ip_input.text().strip()
        if not target_ip:
            QMessageBox.warning(self, "输入错误", "请输入目标IP地址")
            return
            
        # 验证IP格式（简单验证）
        if not self.validate_ip(target_ip):
            QMessageBox.warning(self, "输入错误", "请输入有效的IP地址")
            return
            
        # 获取扫描模式
        scan_mode = "tcp" if self.tcp_radio.isChecked() else "udp"
        
        # 获取精简模式设置
        lite_mode = self.lite_mode_checkbox.isChecked()
            
        # 准备参数
        params = {
            'target_ip': target_ip,
            'scan_mode': scan_mode,
            'lite': lite_mode,
            'xml_output': self.xml_output_checkbox.isChecked()
        }
        
        output_dir = self.network_output_input.text().strip()
        if output_dir:
            params['output_dir'] = output_dir
            
        self.start_worker('network_scanner', params)
        
    def validate_ip(self, ip):
        """简单IP地址验证"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
            
    def start_worker(self, module_name, params):
        """启动工作线程"""
        if self.current_worker and self.current_worker.isRunning():
            QMessageBox.warning(self, "正在运行", "已有任务正在执行，请等待完成")
            return
            
        # 清空日志
        self.log_display.clear()
        self.statusBar().showMessage("正在执行...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # 不确定进度的旋转样式
        
        # 创建并启动工作线程
        self.current_worker = WorkerThread(self.module_manager, module_name, params)
        self.current_worker.signals.finished.connect(self.on_worker_finished)
        self.current_worker.signals.log_message.connect(self.append_log)
        self.current_worker.start()
        
    def append_log(self, message):
        """追加日志消息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_display.append(f"[{timestamp}] {message}")
        self.log_display.verticalScrollBar().setValue(
            self.log_display.verticalScrollBar().maximum()
        )
        
    def on_worker_finished(self, success, message):
        """工作线程完成回调"""
        self.progress_bar.setVisible(False)
        self.statusBar().showMessage(message)
        
        if success:
            QMessageBox.information(self, "执行完成", "任务执行成功！")
        else:
            QMessageBox.critical(self, "执行失败", f"任务执行失败: {message}")


def get_version():
    """获取当前版本信息"""
    return "自动化安全测试平台 v1.1.0"


def main():
    """主函数"""
    app = QApplication(sys.argv)
    
    # 设置应用信息
    app.setApplicationName("AutoAIO Security Test Platform")
    app.setApplicationVersion("1.0.2")
    
    # 创建并显示主窗口
    window = SecurityTestGUI()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
