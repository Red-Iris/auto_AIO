#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自动化安全测试平台 - 演示脚本

此脚本演示了如何使用平台的各种功能

Author: Reid Xu
Date: 2026-03-08
"""

import os
from core import ModuleManager
from modules import TLSAnalyzerModule


def get_version():
    """获取当前版本信息"""
    return "自动化安全测试平台 v1.0.2"


def demo_tls_analysis():
    """演示TLS分析功能"""
    print("="*60)
    print("自动化安全测试平台 - TLS分析功能演示")
    print(f"版本: {get_version()}")
    print("="*60)
    
    # 创建模块管理器
    module_manager = ModuleManager()
    
    # 注册TLS分析模块
    module_manager.register_module(TLSAnalyzerModule())
    
    print("\n演示: 如何调用TLS分析模块")
    print("-" * 40)
    print("基本使用方法:")
    print("python test.py <pcap_file_path>")
    print()
    print("查看版本信息:")
    print("python test.py --version")
    print()
    print("查看帮助信息:")
    print("python test.py --help")
    print()
    print("指定输出目录:")
    print("python test.py <pcap_file_path> --output-dir <output_dir>")
    print()
    
    # 演示参数设置
    params = {
        'pcap_file': 'sample_capture.pcapng',  # 示例文件路径
        'output_dir': './demo_output'
    }
    
    print(f"参数: {params}")
    print()
    
    # 尝试执行（因为文件不存在，会提示错误，这是正常的演示）
    print("尝试执行TLS分析模块（由于没有真实文件，这将显示错误信息）:")
    success = module_manager.execute_module('tls_analyzer', params)
    
    if not success:
        print("\n注意: 因为示例文件不存在，所以执行失败，这是正常的。")
        print("当您有一个真实的.pcapng文件时，可以这样使用:")
        print("python test.py your_capture.pcapng")
    
    print("\n" + "="*60)
    print("平台特点:")
    print("1. 模块化设计 - 可轻松扩展新功能")
    print("2. 自动创建时间戳项目目录")
    print("3. 根据提取的域名自动创建子目录")
    print("4. 支持自定义输出目录")
    print("5. 跨平台支持 - Windows/Linux/macOS")
    print("6. 命令行友好 - 支持--help和--version参数")
    print("="*60)


if __name__ == "__main__":
    demo_tls_analysis()