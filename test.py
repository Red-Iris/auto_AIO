#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自动化安全测试平台 - 主程序入口

该模块实现以下功能：
1. 接收用户上传的.pcapng数据包文件
2. 过滤出TLS协议中包含域名/IP的握手包
3. 按照日期时间戳创建项目目录
4. 根据提取出的域名创建子文件夹存储测试记录

Author: Reid Xu
Date: 2026-03-09
"""

import os
import sys
import argparse
from core import ModuleManager, get_default_tshark_path, get_version
from modules import TLSAnalyzerModule, NetworkScannerModule, VulnerabilityScannerModule


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        prog='AutoAIO',
        description='自动化安全测试平台',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""使用示例:
  python test.py tls capture.pcapng                    分析TLS流量包
  python test.py tls capture.pcapng --tshark-path /path/to/tshark    指定TShark路径
  python test.py tls capture.pcapng --generate-certificates         生成证书文件
  python test.py network 192.168.1.1                  扫描目标IP
  python test.py network 192.168.1.1 --xml-output     扫描并生成XML报告
  python test.py --version                            显示版本信息
  python test.py --help                               显示帮助信息
  python test.py --debug tls capture.pcapng           调试模式分析TLS流量包"""
    )
    parser.add_argument('--version', '-v', action='version', version=get_version(), help='显示当前版本')
    parser.add_argument('--debug', action='store_true', help='启用调试模式，显示详细日志')
    
    subparsers = parser.add_subparsers(dest='module', help='可用的模块')
    
    # TLS分析模块
    tls_parser = subparsers.add_parser('tls', help='TLS域名分析模块 - 从抓包文件中提取TLS握手包中的域名信息')
    tls_parser.add_argument('pcap_file', help='输入的.pcapng文件路径')
    tls_parser.add_argument('--output-dir', '-o', help='输出目录路径（默认为当前目录）')
    tls_parser.add_argument('--tshark-path', help='TShark可执行文件路径（默认自动检测）')
    tls_parser.add_argument('--generate-certificates', action='store_true', help='为每个域名生成证书、密钥和自签名文件')
    
    # 网络扫描模块
    net_parser = subparsers.add_parser('network', help='网络扫描模块 - 使用nmap扫描目标设备开放端口和服务')
    net_parser.add_argument('target_ip', help='目标IP地址')
    net_parser.add_argument('--xml-output', action='store_true', help='生成XML格式的扫描报告')
    net_parser.add_argument('--output-dir', '-o', help='输出目录路径（默认为当前目录）')
    
    # 漏洞扫描模块（预留）
    vuln_parser = subparsers.add_parser('vuln', help='漏洞扫描模块 - 扫描目标设备可能存在的安全漏洞（开发中）')
    vuln_parser.add_argument('target', help='目标IP或域名')
    vuln_parser.add_argument('--output-dir', '-o', help='输出目录路径（默认为当前目录）')
    
    args = parser.parse_args()
    
    # 如果没有提供模块，显示帮助信息
    if not args.module:
        parser.print_help()
        sys.exit(1)
    
    # 创建模块管理器并注册所有模块（根据是否启用调试模式）
    module_manager = ModuleManager()
    module_manager.register_module(TLSAnalyzerModule(debug_mode=args.debug))
    module_manager.register_module(NetworkScannerModule(debug_mode=args.debug))
    module_manager.register_module(VulnerabilityScannerModule(debug_mode=args.debug))
    
    # 准备参数
    params = {
        'output_dir': args.output_dir
    }
    
    # 根据模块类型执行相应功能
    try:
        if args.module == 'tls':
            params['pcap_file'] = args.pcap_file
            # 如果用户指定了TShark路径，则使用该路径；否则尝试获取默认路径
            if args.tshark_path:
                params['tshark_path'] = args.tshark_path
            else:
                default_tshark_path = get_default_tshark_path()
                if default_tshark_path:
                    params['tshark_path'] = default_tshark_path
                else:
                    print("警告: 未找到TShark，请确保已安装Wireshark并指定TShark路径")
                    print("提示: 可以通过 --tshark-path 参数指定TShark可执行文件的路径")
                    sys.exit(1)
            # 添加证书生成参数
            params['generate_certificates'] = args.generate_certificates
            success = module_manager.execute_module('tls_analyzer', params)
        elif args.module == 'network':
            params['target_ip'] = args.target_ip
            params['xml_output'] = args.xml_output
            success = module_manager.execute_module('network_scanner', params)
        elif args.module == 'vuln':
            params['target'] = args.target
            success = module_manager.execute_module('vulnerability_scanner', params)
        else:
            print(f"未知模块: {args.module}")
            sys.exit(1)
        
        if success:
            print(f"{args.module} 模块执行完成")
        else:
            print(f"{args.module} 模块执行失败")
            sys.exit(1)
            
    except ValueError as e:
        print(f"错误: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"处理过程中发生错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()