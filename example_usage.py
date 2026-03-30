#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自动化安全测试平台 - 示例使用脚本

Author: Reid Xu
Date: 2026-03-08
"""

from core import ModuleManager
from modules import TLSAnalyzerModule, NetworkScannerModule, VulnerabilityScannerModule


def get_version():
    """获取当前版本信息"""
    return "自动化安全测试平台 v1.0.2"


def main():
    """演示如何使用模块化平台"""
    print(f"当前版本: {get_version()}")
    
    # 创建模块管理器
    module_manager = ModuleManager()
    
    # 注册所有可用模块
    module_manager.register_module(TLSAnalyzerModule())
    module_manager.register_module(NetworkScannerModule())
    module_manager.register_module(VulnerabilityScannerModule())
    
    # 列出所有模块
    print("可用模块列表:")
    for module_name in module_manager.list_modules():
        module = module_manager.modules[module_name]
        print(f"- {module_name}: {module.description()}")
    
    print("\n" + "="*50)
    print("命令行选项:")
    print("python test.py --help          查看帮助信息")
    print("python test.py --version       查看版本信息")
    print("python test.py <file.pcapng>   分析抓包文件")
    print("="*50)


if __name__ == "__main__":
    main()