#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自动化安全测试平台 - 核心组件

包含基础类和核心功能组件

Author: Reid Xu
Date: 2026-03-07
"""

import os
import sys
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

__version__ = "2.1.0"


def get_version():
    """获取当前版本信息"""
    return f"自动化安全测试平台 v{__version__}"


class BaseModule(ABC):
    """
    功能模块基类
    所有功能模块都需要继承此类并实现相应的方法
    """
    
    @abstractmethod
    def name(self) -> str:
        """返回模块名称"""
        pass
    
    @abstractmethod
    def description(self) -> str:
        """返回模块描述"""
        pass
    
    @abstractmethod
    def execute(self, params: Dict[str, Any]) -> bool:
        """
        执行模块功能
        
        Args:
            params (Dict[str, Any]): 参数字典
            
        Returns:
            bool: 是否成功执行
        """
        pass


class ModuleManager:
    """
    模块管理器
    负责注册、管理和执行各种功能模块
    """
    
    def __init__(self):
        self.modules = {}
    
    def register_module(self, module):
        """
        注册模块
        
        Args:
            module: 模块实例
        """
        self.modules[module.name()] = module
        print(f"模块已注册: {module.name()} - {module.description()}")
    
    def list_modules(self):
        """返回所有已注册模块的名称列表"""
        return list(self.modules.keys())

    def execute_module(self, module_name: str, params: Dict[str, Any] = None) -> bool:
        """
        执行指定模块
        
        Args:
            module_name (str): 模块名称
            params (Dict[str, Any]): 参数字典
            
        Returns:
            bool: 是否成功执行
        """
        if module_name not in self.modules:
            print(f"模块不存在: {module_name}")
            return False
        
        module = self.modules[module_name]
        if params is None:
            params = {}
        
        return module.execute(params)


class ProjectManager:
    """
    项目管理器
    负责创建和管理项目目录结构
    """
    
    def __init__(self, base_dir: str = None):
        """
        初始化项目管理器
        
        Args:
            base_dir (str): 基础目录，默认为当前目录
        """
        if base_dir is None:
            self.base_dir = Path.cwd()
        else:
            self.base_dir = Path(base_dir)
        
    def create_project_directory(self) -> Path:
        """
        创建项目主目录
        
        Returns:
            Path: 项目主目录路径
        """
        # 使用当前日期时间戳创建项目目录
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.project_dir = self.base_dir / f"security_test_{timestamp}"
        
        # 创建项目主目录
        self.project_dir.mkdir(parents=True, exist_ok=True)
        print(f"创建项目目录: {self.project_dir}")
        
        return self.project_dir
    
    def create_subdirectory(self, items: List[str]):
        """
        为列表中的每个项目创建子目录

        Args:
            items (List[str]): 项目名称列表
        """
        for item in items:
            safe_item = sanitize_filename(item)
            item_dir = self.project_dir / safe_item
            item_dir.mkdir(exist_ok=True)
            print(f"创建子目录: {item_dir}")


def sanitize_filename(name: str) -> str:
    """将字符串中的非法文件名字符替换为下划线"""
    illegal_chars = '/\\:*?"<>|'
    result = str(name)
    for char in illegal_chars:
        result = result.replace(char, '_')
    return result


def get_default_tshark_path():
    """
    获取系统默认的TShark路径。

    查找策略（按优先级）：
    1. shutil.which('tshark') — 跨平台，查系统PATH
    2. 各平台常见安装路径
    """
    # 1) 优先通过 PATH 查找（Linux/macOS 通常能命中，Windows 装了 Wireshark 并勾选PATH也行）
    from_path = shutil.which('tshark')
    if from_path and os.path.isfile(from_path):
        return from_path

    # 2) 平台特有路径回退
    if sys.platform == 'win32':
        candidates = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"D:\Wireshark\tshark.exe",
            r"E:\Wireshark\tshark.exe",
        ]
        # 同时扫描所有盘符下的常见目录（适配非系统盘安装）
        for drive in ['C', 'D', 'E', 'F', 'G']:
            candidates.append(rf"{drive}:\software\Wireshark\tshark.exe")
            candidates.append(rf"{drive}:\software\wireshark\tshark.exe")
            candidates.append(rf"{drive}:\Wireshark\tshark.exe")

        for p in candidates:
            if os.path.isfile(p):
                return p
    elif sys.platform == 'darwin':
        candidates = [
            '/usr/local/bin/tshark',
            '/opt/local/bin/tshark',
            '/Applications/Wireshark.app/Contents/MacOS/tshark',
        ]
        for p in candidates:
            if os.path.isfile(p):
                return p
    else:
        candidates = [
            '/usr/bin/tshark',
            '/usr/local/bin/tshark',
        ]
        for p in candidates:
            if os.path.isfile(p):
                return p

    return None