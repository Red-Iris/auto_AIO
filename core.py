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
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List


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
            # 替换可能不合法的字符
            safe_item = str(item).replace('/', '_').replace('\\', '_').replace('*', '_').replace('?', '_').replace('"', '_').replace('<', '_').replace('>', '_').replace('|', '_')
            item_dir = self.project_dir / safe_item
            item_dir.mkdir(exist_ok=True)
            print(f"创建子目录: {item_dir}")


def get_default_tshark_path():
    """
    获取系统默认的TShark路径
    """
    possible_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        r"C:\Wireshark\tshark.exe",
        r"E:\Wireshark\tshark.exe"  # 添加E盘路径
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    return None