#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AutoAIO Security Test Platform - GUI (PyQt6)

Author: Reid Xu
Date: 2026-03-10
"""

import sys
import os
import asyncio
import logging
from pathlib import Path
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QFileDialog,
    QGroupBox, QCheckBox, QMessageBox, QProgressBar,
    QRadioButton, QComboBox, QListWidget, QListWidgetItem,
    QStackedWidget, QScrollArea, QFrame, QSizePolicy, QSplitter
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QThread, QRectF, QPointF
from PyQt6.QtGui import QFont, QPainter, QColor, QBrush, QPen, QPainterPath

from core import ModuleManager, get_default_tshark_path, get_version, __version__
from modules import TLSAnalyzerModule, NetworkScannerModule, VulnerabilityScannerModule
import config as app_config


# ═══════════════════════════════════════════
# Theme
# ═══════════════════════════════════════════

def _theme_file(theme_name: str) -> str:
    return str(Path(__file__).resolve().parent / f'style_{theme_name}.qss')


def _load_qss(theme_name: str) -> str:
    path = _theme_file(theme_name)
    if os.path.isfile(path):
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    return ''


# ═══════════════════════════════════════════
# Worker (unchanged business logic)
# ═══════════════════════════════════════════

class WorkerSignals(QObject):
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
            if sys.platform == 'win32':
                loop = asyncio.ProactorEventLoop()
            else:
                loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            original_print = print

            def custom_print(*args, **kwargs):
                message = ' '.join(str(arg) for arg in args)
                self.signals.log_message.emit(message)
                original_print(*args, **kwargs)

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

            success = self.module_manager.execute_module(self.module_name, self.params)
            result_msg = "OK" if success else "FAILED"
            self.signals.finished.emit(success, result_msg)
            loop.close()

        except Exception as e:
            self.signals.log_message.emit(f"[ERROR] {e}")
            self.signals.finished.emit(False, f"FAILED: {e}")
            try:
                if loop:
                    loop.close()
            except Exception:
                pass
        finally:
            if module_logger and gui_log_handler:
                module_logger.removeHandler(gui_log_handler)
                gui_log_handler.close()
            if original_print is not None:
                import builtins
                builtins.print = original_print


# ═══════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════

def _card(title: str) -> QGroupBox:
    """Create a styled card group box."""
    g = QGroupBox(title)
    g.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    return g


def _browse_btn(text: str = '\U0001f4c2  浏览...') -> QPushButton:
    """Create a standard browse button."""
    btn = QPushButton(text)
    btn.setProperty('cssClass', 'browse')
    return btn


def _mono_font() -> QFont:
    return QFont('Cascadia Code', 10) or QFont('Consolas', 10)


def _page_container(widget: QWidget) -> QScrollArea:
    """Wrap a widget in a scroll area for small-window friendliness."""
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setWidget(widget)
    return scroll


# ═══════════════════════════════════════════
# Theme toggle switch
# ═══════════════════════════════════════════

class ThemeToggle(QWidget):
    """iOS-style sliding toggle switch for dark/light theme."""
    toggled = pyqtSignal(str)

    TRACK_DARK = QColor('#252640')
    TRACK_LIGHT = QColor('#d8dae2')
    KNOB_COLOR = QColor('#ffffff')
    ACTIVE_DARK = QColor('#6c5ce7')
    ACTIVE_LIGHT = QColor('#4f46e5')

    def __init__(self, initial='dark', parent=None):
        super().__init__(parent)
        self._state = initial
        self._anim_value = 1.0 if initial == 'dark' else 0.0
        self.setFixedSize(52, 28)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip('点击切换深色 / 浅色主题')

    def state(self):
        return self._state

    def setState(self, s):
        self._state = s
        self._anim_value = 1.0 if s == 'dark' else 0.0
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        margin = 3
        knob_r = (h - margin * 2) / 2
        track_rect = QRectF(0, 0, w, h)

        # Track
        _, track_gray = (
            (self.ACTIVE_DARK, self.TRACK_DARK)
            if self._state == 'dark'
            else (self.ACTIVE_LIGHT, self.TRACK_LIGHT)
        )
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(track_gray))
        p.drawRoundedRect(track_rect, h / 2, h / 2)

        # Knob position: dark=right, light=left
        travel = w - (margin + knob_r) * 2
        cx = margin + knob_r + travel * self._anim_value
        cy = h / 2

        # Knob shadow
        shadow_path = QPainterPath()
        shadow_path.addEllipse(QPointF(cx + 0.5, cy + 1), knob_r, knob_r)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor(0, 0, 0, 30)))
        p.drawPath(shadow_path)

        # Knob
        p.setBrush(QBrush(self.KNOB_COLOR))
        p.drawEllipse(QPointF(cx, cy), knob_r, knob_r)

        # Icon inside knob
        icon_text = '☾' if self._state == 'dark' else '☀'
        p.setPen(QColor('#333333') if self._state != 'dark' else QColor('#f59e0b'))
        font = QFont('Segoe UI Symbol', int(knob_r * 1.15))
        p.setFont(font)
        p.drawText(QRectF(cx - knob_r, cy - knob_r, knob_r * 2, knob_r * 2),
                   Qt.AlignmentFlag.AlignCenter, icon_text)
        p.end()

    def mousePressEvent(self, event):
        pass  # handle on release for better UX

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._state = 'light' if self._state == 'dark' else 'dark'
            self._anim_value = 1.0 if self._state == 'dark' else 0.0
            self.update()
            self.toggled.emit(self._state)


# ═══════════════════════════════════════════
# Sidebar
# ═══════════════════════════════════════════

NAV_ITEMS = [
    ('tls',      '\U0001f512  TLS 域名分析',   'PCAP 抓包文件分析，提取 TLS 域名并生成证书'),
    ('network',  '\U0001f310  网络扫描',        '基于 Nmap 的 TCP/UDP 端口与服务扫描'),
    ('vuln',     '\U0001f6e1  漏洞扫描',        '固件 / 二进制文件 CVE 已知漏洞检测'),
    ('syscheck', '\U0001f527  系统检查',        '检测本机外部工具依赖是否就绪'),
]


class SecurityTestGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle(get_version())
        self.setGeometry(100, 100, 1260, 720)
        self.setMinimumSize(980, 600)

        self._saved_config = app_config.load_config()
        self._current_theme = app_config.get_config_value('theme', 'dark')

        self.module_manager = ModuleManager()
        self.module_manager.register_module(TLSAnalyzerModule(debug_mode=True))
        self.module_manager.register_module(NetworkScannerModule(debug_mode=True))
        self.module_manager.register_module(VulnerabilityScannerModule(debug_mode=True))

        self.current_worker = None

        self._setup_ui()
        self._apply_theme()
        self._apply_saved_config()

    # ————————————————————————————————
    # Theme
    # ————————————————————————————————

    def _apply_theme(self):
        qss = _load_qss(self._current_theme)
        QApplication.instance().setStyleSheet(qss)
        for widget in QApplication.instance().allWidgets():
            widget.style().unpolish(widget)
            widget.style().polish(widget)
        if hasattr(self, '_theme_toggle'):
            self._theme_toggle.setState(self._current_theme)

    def _on_toggle_switched(self, state):
        if state != self._current_theme:
            self._toggle_theme()

    def _toggle_theme(self):
        self._current_theme = 'light' if self._current_theme == 'dark' else 'dark'
        app_config.set_config_value('theme', self._current_theme)
        self._apply_theme()

    # ————————————————————————————————
    # UI skeleton
    # ————————————————————————————————

    def _setup_ui(self):
        # Root splitter: sidebar | content+log
        body = QWidget()
        self.setCentralWidget(body)
        root = QHBoxLayout(body)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---- Sidebar ----
        sidebar_frame = QFrame()
        sidebar_frame.setObjectName('sidebar')
        sidebar_frame.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar_frame)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        # App title in sidebar
        title_lbl = QLabel('  AutoAIO')
        title_lbl.setObjectName('sidebarTitle')
        title_lbl.setFixedHeight(52)
        sidebar_layout.addWidget(title_lbl)

        # Nav list
        self.nav_list = QListWidget()
        self.nav_list.setObjectName('navList')
        self.nav_list.setSpacing(2)
        self.nav_list.setFixedWidth(220)
        for key, label, tip in NAV_ITEMS:
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setToolTip(tip)
            self.nav_list.addItem(item)
        self.nav_list.setCurrentRow(0)
        self.nav_list.currentRowChanged.connect(self._on_nav_changed)
        sidebar_layout.addWidget(self.nav_list)

        # Theme toggle row
        toggle_row = QFrame()
        toggle_row.setObjectName('toggleRow')
        toggle_row.setFixedHeight(48)
        toggle_layout = QHBoxLayout(toggle_row)
        toggle_layout.setContentsMargins(14, 0, 12, 0)
        toggle_lbl = QLabel('主题')
        toggle_lbl.setObjectName('toggleLabel')
        toggle_layout.addWidget(toggle_lbl)
        toggle_layout.addStretch()
        self._theme_toggle = ThemeToggle(self._current_theme, self)
        self._theme_toggle.toggled.connect(self._on_toggle_switched)
        toggle_layout.addWidget(self._theme_toggle)
        sidebar_layout.addWidget(toggle_row)

        # Version in sidebar bottom
        ver_lbl = QLabel(f'  v{__version__}')
        ver_lbl.setObjectName('sidebarVersion')
        ver_lbl.setFixedHeight(36)
        sidebar_layout.addWidget(ver_lbl)

        root.addWidget(sidebar_frame)

        # ---- Right side: pages + log + status ----
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Vertical splitter: pages (top) | log panel (bottom, draggable)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(5)

        # Stacked pages
        self.stack = QStackedWidget()
        self.stack.addWidget(_page_container(self._tls_page()))
        self.stack.addWidget(_page_container(self._network_page()))
        self.stack.addWidget(_page_container(self._vuln_page()))
        self.stack.addWidget(_page_container(self._syscheck_page()))
        splitter.addWidget(self.stack)

        # Log bottom container
        log_bottom = QWidget()
        log_bottom_layout = QVBoxLayout(log_bottom)
        log_bottom_layout.setContentsMargins(0, 0, 0, 0)
        log_bottom_layout.setSpacing(0)

        log_bar = QFrame()
        log_bar.setObjectName('logBar')
        log_bar.setFixedHeight(28)
        log_bar_layout = QHBoxLayout(log_bar)
        log_bar_layout.setContentsMargins(12, 0, 12, 0)
        log_lbl = QLabel('\U0001f4dc  执行日志')
        log_lbl.setObjectName('logBarLabel')
        self._log_toggle_btn = QPushButton('▼')
        self._log_toggle_btn.setObjectName('logToggle')
        self._log_toggle_btn.setFixedSize(24, 22)
        self._log_toggle_btn.clicked.connect(self._toggle_log)
        log_bar_layout.addWidget(log_lbl)
        log_bar_layout.addStretch()
        log_bar_layout.addWidget(self._log_toggle_btn)
        log_bottom_layout.addWidget(log_bar)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(_mono_font())
        self.log_display.setObjectName('logDisplay')
        self.log_display.setMinimumHeight(60)
        log_bottom_layout.addWidget(self.log_display, stretch=1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setTextVisible(False)
        log_bottom_layout.addWidget(self.progress_bar)

        splitter.addWidget(log_bottom)
        splitter.setSizes([440, 240])
        right_layout.addWidget(splitter, stretch=1)

        # Status bar
        self.statusBar().showMessage('就绪')

        root.addWidget(right, stretch=1)

    def _toggle_log(self):
        visible = self.log_display.isVisible()
        self.log_display.setVisible(not visible)
        self._log_toggle_btn.setText('▶' if not visible else '▼')

    def _on_nav_changed(self, index: int):
        self.stack.setCurrentIndex(index)

    # ————————————————————————————————
    # Page: TLS Analysis
    # ————————————————————————————————

    def _tls_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName('tlsPage')
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 16)
        layout.setSpacing(14)

        header = QLabel('TLS 域名分析')
        header.setObjectName('pageHeader')
        layout.addWidget(header)

        desc = QLabel('从 PCAP 抓包文件中提取 TLS SNI 域名信息，并可自动生成匹配证书。')
        desc.setWordWrap(True)
        desc.setObjectName('pageDesc')
        layout.addWidget(desc)

        # Card: PCAP File
        c1 = _card('PCAP 文件')
        c1l = QHBoxLayout()
        self.tls_file_input = QLineEdit()
        self.tls_file_input.setPlaceholderText('拖拽 .pcap/.pcapng 文件到此处，或点击浏览')
        self.tls_file_input.setAcceptDrops(True)
        b1 = _browse_btn()
        b1.clicked.connect(self.browse_tls_file)
        c1l.addWidget(self.tls_file_input)
        c1l.addWidget(b1)
        c1.setLayout(c1l)
        layout.addWidget(c1)

        # Card: Options
        c2 = _card('选项')
        c2l = QVBoxLayout()
        c2l.setSpacing(8)

        # TShark path row
        tr = QHBoxLayout()
        tr.addWidget(QLabel('TShark 路径'))
        self.tshark_path_input = QLineEdit()
        default_tshark = get_default_tshark_path()
        if default_tshark:
            root, ext = os.path.splitext(default_tshark)
            self.tshark_path_input.setText(root + ext.lower())
        else:
            self.tshark_path_input.setPlaceholderText('自动检测（留空即可）')
        tb = _browse_btn()
        tb.clicked.connect(self.browse_tshark_path)
        tr.addWidget(self.tshark_path_input)
        tr.addWidget(tb)
        c2l.addLayout(tr)

        # Output dir row
        orow = QHBoxLayout()
        orow.addWidget(QLabel('输出目录'))
        self.tls_output_input = QLineEdit()
        self.tls_output_input.setPlaceholderText('默认为当前目录')
        ob = _browse_btn()
        ob.clicked.connect(self.browse_output_dir)
        orow.addWidget(self.tls_output_input)
        orow.addWidget(ob)
        c2l.addLayout(orow)

        self.generate_cert_checkbox = QCheckBox('为每个域名生成证书、密钥和自签名文件')
        c2l.addWidget(self.generate_cert_checkbox)

        c2.setLayout(c2l)
        layout.addWidget(c2)

        # Persist config
        self.tshark_path_input.editingFinished.connect(
            lambda: app_config.set_tshark_path(self.tshark_path_input.text().strip()))
        self.tls_output_input.editingFinished.connect(
            lambda: app_config.set_default_output_dir(self.tls_output_input.text().strip()))

        # Execute
        btn = QPushButton('▶  开始 TLS 分析')
        btn.setProperty('cssClass', 'primary-green')
        btn.clicked.connect(self.execute_tls_analysis)
        layout.addWidget(btn)

        layout.addStretch()
        return page

    # ————————————————————————————————
    # Page: Network Scan
    # ————————————————————————————————

    def _network_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName('networkPage')
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 16)
        layout.setSpacing(14)

        header = QLabel('网络扫描')
        header.setObjectName('pageHeader')
        layout.addWidget(header)

        desc = QLabel('基于 Nmap 对目标 IP 进行 TCP/UDP 端口扫描与服务识别。')
        desc.setWordWrap(True)
        desc.setObjectName('pageDesc')
        layout.addWidget(desc)

        # Card: Target
        c1 = _card('目标')
        c1l = QHBoxLayout()
        c1l.addWidget(QLabel('IP 地址'))
        self.target_ip_input = QLineEdit()
        self.target_ip_input.setPlaceholderText('例如: 192.168.1.1')
        c1l.addWidget(self.target_ip_input)
        c1.setLayout(c1l)
        layout.addWidget(c1)

        # Card: Scan Mode
        c2 = _card('扫描模式')
        c2l = QHBoxLayout()
        self.tcp_radio = QRadioButton('TCP 扫描')
        self.udp_radio = QRadioButton('UDP 扫描')
        self.tcp_radio.setChecked(True)
        c2l.addWidget(self.tcp_radio)
        c2l.addWidget(self.udp_radio)
        c2l.addStretch()
        c2.setLayout(c2l)
        layout.addWidget(c2)

        # Card: Options
        c3 = _card('选项')
        c3l = QVBoxLayout()
        c3l.setSpacing(8)
        self.lite_mode_checkbox = QCheckBox('精简模式（仅常用端口，速度更快）')
        self.xml_output_checkbox = QCheckBox('生成 XML 格式报告')
        c3l.addWidget(self.lite_mode_checkbox)
        c3l.addWidget(self.xml_output_checkbox)

        orow = QHBoxLayout()
        orow.addWidget(QLabel('输出目录'))
        self.network_output_input = QLineEdit()
        self.network_output_input.setPlaceholderText('默认为当前目录')
        ob = _browse_btn()
        ob.clicked.connect(lambda: self.browse_output_dir_network())
        orow.addWidget(self.network_output_input)
        orow.addWidget(ob)
        c3l.addLayout(orow)

        c3.setLayout(c3l)
        layout.addWidget(c3)

        self.network_output_input.editingFinished.connect(
            lambda: app_config.set_default_output_dir(self.network_output_input.text().strip()))

        btn = QPushButton('▶  开始网络扫描')
        btn.setProperty('cssClass', 'primary-blue')
        btn.clicked.connect(self.execute_network_scan)
        layout.addWidget(btn)

        layout.addStretch()
        return page

    # ————————————————————————————————
    # Page: Vulnerability Scan (fixed layout)
    # ————————————————————————————————

    def _vuln_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName('vulnPage')
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 16)
        layout.setSpacing(14)

        header = QLabel('漏洞扫描')
        header.setObjectName('pageHeader')
        layout.addWidget(header)

        desc = QLabel('基于 cve-bin-tool 对固件 / 二进制文件进行已知 CVE 漏洞检测。')
        desc.setWordWrap(True)
        desc.setObjectName('pageDesc')
        layout.addWidget(desc)

        # Card: Target
        c1 = _card('扫描目标')
        c1l = QVBoxLayout()
        c1l.setSpacing(8)
        trow = QHBoxLayout()
        self.vuln_target_input = QLineEdit()
        self.vuln_target_input.setPlaceholderText('选择固件目录或二进制文件（支持拖拽）')
        self.vuln_target_input.setAcceptDrops(True)
        trow.addWidget(self.vuln_target_input)
        c1l.addLayout(trow)
        tbrow = QHBoxLayout()
        b_dir = QPushButton('\U0001f4c1  选择目录')
        b_dir.clicked.connect(self.browse_vuln_dir)
        b_file = QPushButton('\U0001f4c4  选择文件')
        b_file.clicked.connect(self.browse_vuln_file)
        tbrow.addWidget(b_dir)
        tbrow.addWidget(b_file)
        tbrow.addStretch()
        c1l.addLayout(tbrow)
        c1.setLayout(c1l)
        layout.addWidget(c1)

        # Card: Report Config — use a GRID for clean alignment
        c2 = _card('报告配置')
        grid = QVBoxLayout()
        grid.setSpacing(8)

        r1 = QHBoxLayout()
        r1.addWidget(QLabel('报告格式'))
        self.vuln_format_combo = QComboBox()
        self.vuln_format_combo.addItems(['csv', 'json', 'html', 'console', 'pdf'])
        self.vuln_format_combo.setCurrentText('csv')
        r1.addWidget(self.vuln_format_combo)
        r1.addSpacing(24)
        r1.addWidget(QLabel('数据库更新策略'))
        self.vuln_update_combo = QComboBox()
        self.vuln_update_combo.addItems(['daily', 'now', 'never', 'latest'])
        self.vuln_update_combo.setCurrentText('daily')
        self.vuln_update_combo.setToolTip('daily=按日更新; now=立即更新; never=不更新; latest=仅最新CVE')
        r1.addWidget(self.vuln_update_combo)
        r1.addStretch()
        grid.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel('CVSS 下限'))
        self.vuln_cvss_input = QLineEdit()
        self.vuln_cvss_input.setPlaceholderText('留空=不限')
        self.vuln_cvss_input.setFixedWidth(80)
        r2.addWidget(self.vuln_cvss_input)
        r2.addSpacing(24)
        r2.addWidget(QLabel('严重级别过滤'))
        self.vuln_severity_combo = QComboBox()
        self.vuln_severity_combo.addItems(['(不限)', 'low', 'medium', 'high', 'critical'])
        self.vuln_severity_combo.setCurrentText('(不限)')
        r2.addWidget(self.vuln_severity_combo)
        r2.addStretch()
        grid.addLayout(r2)

        c2.setLayout(grid)
        layout.addWidget(c2)

        # Card: Advanced
        c3 = _card('高级选项')
        c3l = QVBoxLayout()
        c3l.setSpacing(8)

        ar1 = QHBoxLayout()
        ar1.addWidget(QLabel('NVD API Key'))
        self.vuln_apikey_input = QLineEdit()
        self.vuln_apikey_input.setPlaceholderText('可选，填写后可提升 API 限速')
        ar1.addWidget(self.vuln_apikey_input)
        c3l.addLayout(ar1)

        ar2 = QHBoxLayout()
        self.vuln_offline_checkbox = QCheckBox('离线模式（不联网更新数据库）')
        self.vuln_detailed_checkbox = QCheckBox('详细 CVE 描述')
        self.vuln_detailed_checkbox.setChecked(True)
        ar2.addWidget(self.vuln_offline_checkbox)
        ar2.addWidget(self.vuln_detailed_checkbox)
        ar2.addStretch()
        c3l.addLayout(ar2)

        ar3 = QHBoxLayout()
        ar3.addWidget(QLabel('cve-bin-tool 路径'))
        self.vuln_tool_input = QLineEdit()
        self.vuln_tool_input.setPlaceholderText('留空=自动查找（PATH / tools / 环境变量）')
        tb = _browse_btn()
        tb.clicked.connect(self.browse_vuln_tool_path)
        ar3.addWidget(self.vuln_tool_input)
        ar3.addWidget(tb)
        c3l.addLayout(ar3)

        c3.setLayout(c3l)
        layout.addWidget(c3)

        # Card: Output
        c4 = _card('输出')
        c4l = QHBoxLayout()
        c4l.addWidget(QLabel('输出目录'))
        self.vuln_output_input = QLineEdit()
        self.vuln_output_input.setPlaceholderText('默认为当前目录')
        ob = _browse_btn()
        ob.clicked.connect(self.browse_vuln_output_dir)
        c4l.addWidget(self.vuln_output_input)
        c4l.addWidget(ob)
        c4.setLayout(c4l)
        layout.addWidget(c4)

        # Persist config
        self.vuln_tool_input.editingFinished.connect(
            lambda: app_config.set_cve_bin_tool_path(self.vuln_tool_input.text().strip()))
        self.vuln_apikey_input.editingFinished.connect(
            lambda: app_config.set_nvd_api_key(self.vuln_apikey_input.text().strip()))
        self.vuln_output_input.editingFinished.connect(
            lambda: app_config.set_default_output_dir(self.vuln_output_input.text().strip()))

        btn = QPushButton('▶  开始漏洞扫描')
        btn.setProperty('cssClass', 'primary-orange')
        btn.clicked.connect(self.execute_vulnerability_scan)
        layout.addWidget(btn)

        layout.addStretch()
        return page

    # ————————————————————————————————
    # Page: System Check
    # ————————————————————————————————

    def _syscheck_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName('syscheckPage')
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 16)
        layout.setSpacing(14)

        header = QLabel('系统检查')
        header.setObjectName('pageHeader')
        layout.addWidget(header)

        desc = QLabel('检测本机是否已安装所有必需的外部工具。')
        desc.setWordWrap(True)
        desc.setObjectName('pageDesc')
        layout.addWidget(desc)

        check_btn = QPushButton('✓  开始系统检查')
        check_btn.setProperty('cssClass', 'primary-slate')
        check_btn.clicked.connect(self.run_system_check)
        layout.addWidget(check_btn)

        self.syscheck_display = QTextEdit()
        self.syscheck_display.setReadOnly(True)
        self.syscheck_display.setProperty('cssClass', 'syscheck')
        self.syscheck_display.setFont(_mono_font())
        self.syscheck_display.setMinimumHeight(300)
        layout.addWidget(self.syscheck_display, stretch=1)

        return page

    # ————————————————————————————————
    # System check logic
    # ————————————————————————————————

    def run_system_check(self):
        self.syscheck_display.clear()
        self.syscheck_display.append('正在检测系统环境...\n')

        result = app_config.health_check()

        def status_icon(ok):
            return '  [OK]' if ok else '[MISS]'

        items = [
            ('Python', result['python']),
            ('TShark (Wireshark)', result['tshark']),
            ('Nmap', result['nmap']),
            ('OpenSSL', result['openssl']),
            ('cve-bin-tool', result['cve_bin_tool']),
        ]

        for name, info in items:
            ok = info.get('ok', False)
            icon = status_icon(ok)
            self.syscheck_display.append(f'{icon} {name}')
            if info.get('version'):
                self.syscheck_display.append(f'      版本: {info["version"]}')
            if info.get('path'):
                self.syscheck_display.append(f'      路径: {info["path"]}')
            if info.get('configured_path') and not ok:
                self.syscheck_display.append(f'      已配置路径(无效): {info["configured_path"]}')
            self.syscheck_display.append('')

        if result['all_ok']:
            self.syscheck_display.append('=== 所有工具就绪，可以正常使用 ===')
        else:
            self.syscheck_display.append('=== 存在缺失工具，请参考上方提示安装 ===')
            self.syscheck_display.append('')
            self.syscheck_display.append('安装指引:')
            self.syscheck_display.append('  Wireshark/TShark: https://www.wireshark.org/download.html')
            self.syscheck_display.append('  Nmap: https://nmap.org/download.html')
            self.syscheck_display.append('  OpenSSL (Windows): https://slproweb.com/products/Win32OpenSSL.html')
            self.syscheck_display.append('  cve-bin-tool: 运行项目目录下的 setup.ps1 一键安装')

    # ————————————————————————————————
    # File dialogs
    # ————————————————————————————————

    def browse_tls_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, '选择PCAP文件', '', 'PCAP Files (*.pcap *.pcapng);;All Files (*)')
        if file_path:
            self.tls_file_input.setText(file_path)

    def browse_tshark_path(self):
        if sys.platform == 'win32':
            file_path, _ = QFileDialog.getOpenFileName(
                self, '选择TShark可执行文件', '', 'Executable Files (*.exe);;All Files (*)')
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self, '选择TShark可执行文件', '/usr/bin', 'All Files (*)')
        if file_path:
            self.tshark_path_input.setText(file_path)

    def browse_output_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, '选择输出目录')
        if dir_path:
            self.tls_output_input.setText(dir_path)

    def browse_output_dir_network(self):
        dir_path = QFileDialog.getExistingDirectory(self, '选择输出目录')
        if dir_path:
            self.network_output_input.setText(dir_path)

    def browse_vuln_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, '选择固件目录')
        if dir_path:
            self.vuln_target_input.setText(dir_path)

    def browse_vuln_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, '选择固件或二进制文件', '',
            'All Files (*);;Firmware Files (*.bin *.img *.fw);;Binary Files (*.so *.dll *.exe)')
        if file_path:
            self.vuln_target_input.setText(file_path)

    def browse_vuln_output_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, '选择输出目录')
        if dir_path:
            self.vuln_output_input.setText(dir_path)

    def browse_vuln_tool_path(self):
        if sys.platform == 'win32':
            file_path, _ = QFileDialog.getOpenFileName(
                self, '选择cve-bin-tool或Python解释器', '',
                'Executable Files (*.exe);;All Files (*)')
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self, '选择cve-bin-tool或Python解释器', '/usr/bin', 'All Files (*)')
        if file_path:
            self.vuln_tool_input.setText(file_path)

    # ————————————————————————————————
    # Config backfill
    # ————————————————————————————————

    def _apply_saved_config(self):
        cfg = self._saved_config
        if cfg.get('tshark_path') and os.path.isfile(cfg['tshark_path']):
            self.tshark_path_input.setText(cfg['tshark_path'])
        if cfg.get('default_output_dir') and os.path.isdir(cfg['default_output_dir']):
            self.tls_output_input.setText(cfg['default_output_dir'])
            self.network_output_input.setText(cfg['default_output_dir'])
            self.vuln_output_input.setText(cfg['default_output_dir'])
        if cfg.get('cve_bin_tool_path'):
            self.vuln_tool_input.setText(cfg['cve_bin_tool_path'])
        if cfg.get('nvd_api_key'):
            self.vuln_apikey_input.setText(cfg['nvd_api_key'])

        if not cfg.get('tshark_path'):
            detected = self.tshark_path_input.text().strip()
            if detected and os.path.isfile(detected):
                app_config.set_tshark_path(detected)

    # ————————————————————————————————
    # Execution
    # ————————————————————————————————

    def execute_vulnerability_scan(self):
        target_path = self.vuln_target_input.text().strip()
        if not target_path:
            QMessageBox.warning(self, '输入错误', '请选择待扫描的固件目录或文件')
            return
        if not os.path.exists(target_path):
            QMessageBox.warning(self, '路径错误', '指定的扫描目标不存在')
            return

        params = {'target_path': target_path}
        params['output_format'] = self.vuln_format_combo.currentText()
        params['update_db'] = self.vuln_update_combo.currentText()

        cvss_text = self.vuln_cvss_input.text().strip()
        if cvss_text:
            try:
                params['cvss_limit'] = float(cvss_text)
            except ValueError:
                QMessageBox.warning(self, '输入错误', 'CVSS下限必须是数字')
                return

        severity = self.vuln_severity_combo.currentText()
        if severity != '(不限)':
            params['severity_filter'] = severity

        apikey = self.vuln_apikey_input.text().strip()
        if apikey:
            params['nvd_api_key'] = apikey

        params['offline'] = self.vuln_offline_checkbox.isChecked()

        output_dir = self.vuln_output_input.text().strip()
        if output_dir:
            params['output_dir'] = output_dir

        cve_bin_tool_path = self.vuln_tool_input.text().strip()
        if cve_bin_tool_path:
            params['cve_bin_tool_path'] = cve_bin_tool_path

        self.start_worker('vulnerability_scanner', params)

    def execute_tls_analysis(self):
        pcap_file = self.tls_file_input.text().strip()
        if not pcap_file:
            QMessageBox.warning(self, '输入错误', '请选择PCAP文件')
            return
        if not os.path.exists(pcap_file):
            QMessageBox.warning(self, '文件错误', '指定的PCAP文件不存在')
            return

        params = {'pcap_file': pcap_file}

        tshark_path = self.tshark_path_input.text().strip()
        if tshark_path and os.path.exists(tshark_path):
            params['tshark_path'] = tshark_path

        output_dir = self.tls_output_input.text().strip()
        if output_dir:
            params['output_dir'] = output_dir

        params['generate_certificates'] = self.generate_cert_checkbox.isChecked()
        self.start_worker('tls_analyzer', params)

    def execute_network_scan(self):
        target_ip = self.target_ip_input.text().strip()
        if not target_ip:
            QMessageBox.warning(self, '输入错误', '请输入目标IP地址')
            return
        if not self.validate_ip(target_ip):
            QMessageBox.warning(self, '输入错误', '请输入有效的IP地址')
            return

        scan_mode = 'tcp' if self.tcp_radio.isChecked() else 'udp'
        lite_mode = self.lite_mode_checkbox.isChecked()

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

    @staticmethod
    def validate_ip(ip):
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    # ————————————————————————————————
    # Worker management
    # ————————————————————————————————

    def start_worker(self, module_name, params):
        if self.current_worker and self.current_worker.isRunning():
            QMessageBox.warning(self, '正在运行', '已有任务正在执行，请等待完成')
            return

        self.log_display.clear()
        self.statusBar().showMessage('正在执行...')
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)

        self.current_worker = WorkerThread(self.module_manager, module_name, params)
        self.current_worker.signals.finished.connect(self.on_worker_finished)
        self.current_worker.signals.log_message.connect(self.append_log)
        self.current_worker.start()

    def append_log(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_display.append(f'[{timestamp}] {message}')
        self.log_display.verticalScrollBar().setValue(
            self.log_display.verticalScrollBar().maximum())

    def on_worker_finished(self, success, message):
        self.progress_bar.setVisible(False)
        self.statusBar().showMessage(message)
        if success:
            QMessageBox.information(self, '执行完成', '任务执行成功！')
        else:
            QMessageBox.critical(self, '执行失败', f'任务执行失败: {message}')


# ═══════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    app.setApplicationName('AutoAIO Security Test Platform')
    app.setApplicationVersion(__version__)

    window = SecurityTestGUI()
    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
