#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自动化安全测试平台 - 网络扫描模块使用示例

Author: Reid Xu
Date: 2026-03-09
"""

import sys
from core import ModuleManager, get_version
from modules import NetworkScannerModule


def main():
    """演示如何使用网络扫描模块"""
    print("="*60)
    print("自动化安全测试平台 - 网络扫描模块演示")
    print(f"版本: {get_version()}")
    print("="*60)
    
    # 创建模块管理器
    module_manager = ModuleManager()
    
    # 注册网络扫描模块
    module_manager.register_module(NetworkScannerModule())
    
    print("\n网络扫描模块功能说明:")
    print("- 使用nmap对目标IP进行全端口扫描")
    print("- 检测开放端口及其服务版本")
    print("- 进行操作系统检测")
    print("- 结果保存到nmap_scan子目录")
    print()
    
    print("使用方法:")
    print("1. 确保系统已安装nmap")
    print("2. 运行: python network_scan_example.py <target_ip>")
    print()
    
    # 检查命令行参数
    if len(sys.argv) < 2:
        print("请输入目标IP地址作为参数")
        print("示例: python network_scan_example.py 192.168.1.1")
        return
    
    target_ip = sys.argv[1]
    print(f"目标IP: {target_ip}")
    print()
    
    # 执行网络扫描
    params = {
        'target_ip': target_ip,
        'output_dir': './nmap_results'
    }
    
    success = module_manager.execute_module('network_scanner', params)
    
    if success:
        print("\n网络扫描完成!")
    else:
        print("\n网络扫描失败!")
        sys.exit(1)


if __name__ == "__main__":
    main()