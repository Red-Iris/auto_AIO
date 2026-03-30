#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自动化安全测试平台 - 功能模块实现

Author: Reid Xu
Date: 2026-03-08
"""

import os
import pyshark
import subprocess
import json
import logging
from datetime import datetime
from typing import Dict, Any, Set
from pathlib import Path
from core import BaseModule, ProjectManager


def setup_logging(module_name: str, debug_mode: bool = False):
    """设置日志记录"""
    # 创建logs目录
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 设置日志格式和处理器
    log_filename = os.path.join(log_dir, f"{module_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    # 创建logger
    logger = logging.getLogger(f"{module_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    logger.setLevel(logging.DEBUG)
    
    # 清除之前的处理器
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # 创建文件处理器
    file_handler = logging.FileHandler(log_filename, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # 创建格式器
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    
    # 添加处理器到logger
    logger.addHandler(file_handler)
    
    # 仅在调试模式下添加控制台处理器
    if debug_mode:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger


class TLSAnalyzerModule(BaseModule):
    """
    TLS域名分析模块
    从pcap文件中提取TLS握手包中的服务器名称
    """
    
    def __init__(self, debug_mode: bool = False):
        self.debug_mode = debug_mode
        self.logger = setup_logging('tls_analyzer', debug_mode)
    
    def name(self) -> str:
        return "tls_analyzer"
    
    def description(self) -> str:
        return "TLS域名分析模块 - 从抓包文件中提取TLS握手包中的域名信息"
    
    def execute(self, params: Dict[str, Any]) -> bool:
        """
        执行TLS域名分析
        
        Args:
            params (Dict[str, Any]): 参数字典
                - pcap_file: .pcapng文件路径
                - output_dir: 输出目录路径（可选）
                - tshark_path: TShark可执行文件路径（可选）
                - generate_certificates: 是否生成证书文件（可选，默认False）
                
        Returns:
            bool: 是否成功执行
        """
        pcap_file = params.get('pcap_file')
        tshark_path = params.get('tshark_path')  # 新增TShark路径参数
        generate_certificates = params.get('generate_certificates', False)  # 新增证书生成参数
        
        if not pcap_file:
            self.logger.error("缺少参数 'pcap_file'")
            print("错误: 缺少参数 'pcap_file'")
            return False
        
        if not os.path.exists(pcap_file):
            self.logger.error(f"文件不存在 '{pcap_file}'")
            print(f"错误: 文件不存在 '{pcap_file}'")
            return False
        
        self.logger.info(f"开始分析PCAP文件: {pcap_file}")
        print(f"开始分析PCAP文件: {pcap_file}")
        
        # 提取TLS域名和端口信息
        domain_port_map = self._extract_tls_domains_and_ports(pcap_file, tshark_path)
        
        if not domain_port_map:
            self.logger.warning("未发现TLS握手包中的域名信息")
            print("未发现TLS握手包中的域名信息")
        else:
            domains = set(domain_port_map.keys())
            self.logger.info(f"发现 {len(domains)} 个唯一的域名: {domains}")
            print(f"发现 {len(domains)} 个唯一的域名:")
            for domain in domains:
                print(f"  - {domain} (端口: {domain_port_map[domain]})")
            
            # 创建项目目录结构
            project_manager = ProjectManager(params.get('output_dir'))
            project_dir = project_manager.create_project_directory()
            project_manager.create_subdirectory(list(domains))
            
            self.logger.info(f"项目目录结构已创建完成: {project_dir}")
            print("项目目录结构创建完成")
            
            # 如果需要生成证书，则为每个域名生成证书文件
            if generate_certificates:
                self.logger.info("开始为每个域名生成证书文件...")
                print("开始为每个域名生成证书文件...")
                success = self._generate_certificates_for_domains(domain_port_map, project_manager.project_dir)
                if not success:
                    self.logger.warning("证书生成过程中出现错误，但TLS分析已完成")
                    print("警告: 证书生成过程中出现错误，但TLS分析已完成")
        
        return True

    def _extract_tls_domains_and_ports(self, pcap_file_path: str, tshark_path: str = None) -> Dict[str, int]:
        """
        从pcap文件中提取TLS握手包中的服务器名称和对应的端口
        
        Args:
            pcap_file_path (str): .pcapng文件路径
            tshark_path (str): TShark可执行文件路径（可选）
            
        Returns:
            Dict[str, int]: 包含域名到端口映射的字典
        """
        self.logger.info(f"开始提取TLS域名和端口，文件: {pcap_file_path}")
        domain_port_map = {}
        
        try:
            # 打开pcap文件并解析TLS握手包，如果提供了tshark_path则使用它
            # 同时获取目的端口信息
            if tshark_path:
                self.logger.debug(f"使用自定义TShark路径: {tshark_path}")
                cap = pyshark.FileCapture(
                    pcap_file_path, 
                    display_filter="tls.handshake.extensions_server_name",
                    tshark_path=tshark_path,
                    keep_packets=True
                )
            else:
                cap = pyshark.FileCapture(pcap_file_path, display_filter="tls.handshake.extensions_server_name")
            
            for packet in cap:
                try:
                    if hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake_extensions_server_name'):
                        server_name = packet.tls.handshake_extensions_server_name
                        # 获取目的端口
                        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport'):
                            dst_port = int(packet.tcp.dstport)
                            domain_port_map[server_name] = dst_port
                            self.logger.debug(f"提取到域名: {server_name}, 端口: {dst_port}")
                        else:
                            # 如果无法获取端口，使用默认端口8883
                            domain_port_map[server_name] = 8883
                            self.logger.debug(f"提取到域名: {server_name}, 端口未知，使用默认8883")
                except AttributeError:
                    # 如果没有找到server_name字段或端口字段，则跳过此包
                    continue
                except Exception as e:
                    self.logger.error(f"处理数据包时出现错误: {e}")
                    print(f"处理数据包时出现错误: {e}")
                    continue
                    
            cap.close()
        except Exception as e:
            self.logger.error(f"读取PCAP文件时出现错误: {e}")
        
        self.logger.info(f"共提取到 {len(domain_port_map)} 个域名-端口映射")
        return domain_port_map

    def _extract_cn_from_server_cert(self, domain: str, port: int) -> str:
        """
        从目标服务器的证书中提取Common Name (CN)
        
        Args:
            domain (str): 目标域名
            port (int): TLS端口，默认8883
            
        Returns:
            str: 提取的Common Name，如果失败则返回原始域名
        """
        try:
            # 构建openssl s_client命令
            cmd = ['openssl', 's_client', '-connect', f'{domain}:{port}', '-showcerts']
            
            self.logger.debug(f"执行证书提取命令: {' '.join(cmd)}")
            
            # 执行命令获取证书
            result = subprocess.run(cmd, 
                                  input='',  # 发送空输入以结束连接
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  text=True,
                                  timeout=30)  # 设置超时避免卡住
            
            if result.returncode != 0:
                self.logger.warning(f"无法连接到 {domain}:{port} 获取证书: {result.stderr}")
                return domain  # 返回原始域名作为备选
            
            # 从输出中提取证书部分
            cert_output = result.stdout
            
            # 使用openssl x509解析证书并提取Subject
            cmd2 = ['openssl', 'x509', '-noout', '-text']
            result2 = subprocess.run(cmd2,
                                   input=cert_output,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result2.returncode != 0:
                self.logger.warning(f"无法解析证书: {result2.stderr}")
                return domain  # 返回原始域名作为备选
            
            # 从证书文本中提取Subject行
            cert_text = result2.stdout
            subject_line = None
            for line in cert_text.split('\n'):
                if 'Subject:' in line:
                    subject_line = line.strip()
                    break
            
            if not subject_line:
                self.logger.warning(f"未在证书中找到Subject字段")
                return domain  # 返回原始域名作为备选
            
            self.logger.debug(f"证书Subject: {subject_line}")
            
            # 提取CN字段
            # Subject格式: Subject: C=US, ST=State, L=City, O=Organization, OU=Unit, CN=*.example.com
            cn_start = subject_line.find('CN=')
            if cn_start == -1:
                self.logger.warning(f"未在Subject中找到CN字段")
                return domain  # 返回原始域名作为备选
            
            cn_part = subject_line[cn_start + 3:]  # 跳过'CN='
            # CN字段可能后面还有其他字段，用逗号分隔
            cn_end = cn_part.find(',')
            if cn_end != -1:
                cn_value = cn_part[:cn_end].strip()
            else:
                cn_value = cn_part.strip()
            
            if cn_value:
                self.logger.info(f"从服务器证书提取CN: {cn_value}")
                return cn_value
            else:
                self.logger.warning(f"提取的CN为空")
                return domain
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"连接 {domain}:{port} 超时")
            return domain
        except Exception as e:
            self.logger.error(f"提取证书CN时出现异常: {e}")
            return domain

    def _generate_certificates_for_domains(self, domain_port_map: Dict[str, int], project_dir: Path) -> bool:
        """
        为每个域名生成证书、密钥和自签名文件
        
        Args:
            domain_port_map (Dict[str, int]): 域名到端口的映射字典
            project_dir (Path): 项目主目录路径
            
        Returns:
            bool: 是否成功生成所有证书
        """
        # 验证openssl是否可用
        try:
            result = subprocess.run(['openssl', 'version'], 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True)
            if result.returncode != 0:
                self.logger.error(f"OpenSSL未安装或不可用: {result.stderr}")
                print("错误: OpenSSL未安装或不可用，无法生成证书文件")
                return False
            else:
                self.logger.info("OpenSSL已正确安装")
        except FileNotFoundError:
            self.logger.error("OpenSSL未安装或不在系统PATH中")
            print("错误: OpenSSL未安装或不在系统PATH中，无法生成证书文件")
            return False
        
        all_success = True
        
        for domain, port in domain_port_map.items():
            # 替换可能不合法的字符（仅用于文件夹名）
            safe_domain = str(domain).replace('/', '_').replace('\\', '_').replace('*', '_').replace('?', '_').replace('"', '_').replace('<', '_').replace('>', '_').replace('|', '_')
            domain_dir = project_dir / safe_domain
            
            if not domain_dir.exists():
                self.logger.warning(f"域名目录不存在，跳过证书生成: {domain_dir}")
                continue
            
            self.logger.info(f"为域名 {domain} (端口: {port}) 生成证书文件...")
            print(f"为域名 {domain} (端口: {port}) 生成证书文件...")
            
            try:
                # 先从服务器证书中提取Common Name
                extracted_cn = self._extract_cn_from_server_cert(domain, port)
                self.logger.info(f"使用提取的CN '{extracted_cn}' 生成证书")
                print(f"使用提取的CN '{extracted_cn}' 生成证书")
                
                # 1. 生成私钥
                key_path = domain_dir / "server.key"
                cmd1 = ['openssl', 'genrsa', '-out', str(key_path), '2048']
                self.logger.debug(f"执行命令: {' '.join(cmd1)}")
                result1 = subprocess.run(cmd1, 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        text=True)
                if result1.returncode != 0:
                    self.logger.error(f"生成私钥失败: {result1.stderr}")
                    print(f"生成私钥失败: {result1.stderr}")
                    all_success = False
                    continue
                
                # 2. 生成证书请求文件（CSR）
                csr_path = domain_dir / "server.csr"
                # 准备交互式输入
                # Country Name (2 letter code) [AU]: 11
                # State or Province Name (full name) [Some-State]: 11
                # Locality Name (eg, city) []: 11
                # Organization Name (eg, company) [Internet Widgits Pty Ltd]: 11
                # Organizational Unit Name (eg, section) []: 11
                # Common Name (e.g. server FQDN or YOUR name) []: extracted_cn (使用从服务器证书提取的CN)
                # Email Address []: 1111
                # A challenge password []: 1111
                # An optional company name []: 1111
                input_data = f"11\n11\n11\n11\n11\n{extracted_cn}\n1111\n1111\n1111\n"
                
                cmd2 = ['openssl', 'req', '-new', '-key', str(key_path), '-out', str(csr_path)]
                self.logger.debug(f"执行命令: {' '.join(cmd2)}")
                result2 = subprocess.run(cmd2, 
                                        input=input_data,
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        text=True)
                if result2.returncode != 0:
                    self.logger.error(f"生成CSR失败: {result2.stderr}")
                    print(f"生成CSR失败: {result2.stderr}")
                    all_success = False
                    continue
                
                # 3. 生成自签名证书
                crt_path = domain_dir / "server.crt"
                cmd3 = ['openssl', 'x509', '-req', '-in', str(csr_path), '-signkey', str(key_path), '-out', str(crt_path), '-days', '365']
                self.logger.debug(f"执行命令: {' '.join(cmd3)}")
                result3 = subprocess.run(cmd3, 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        text=True)
                if result3.returncode != 0:
                    self.logger.error(f"生成自签名证书失败: {result3.stderr}")
                    print(f"生成自签名证书失败: {result3.stderr}")
                    all_success = False
                    continue
                
                self.logger.info(f"成功为域名 {domain} 生成证书文件")
                print(f"成功为域名 {domain} 生成证书文件")
                
            except Exception as e:
                self.logger.error(f"生成证书时出现异常: {e}")
                print(f"生成证书时出现异常: {e}")
                all_success = False
        
        return all_success


class NetworkScannerModule(BaseModule):
    """
    网络扫描模块（使用nmap进行全端口扫描）
    """
    
    def __init__(self, debug_mode: bool = False):
        self.debug_mode = debug_mode
        self.logger = setup_logging('network_scanner', debug_mode)
    
    def name(self) -> str:
        return "network_scanner"
    
    def description(self) -> str:
        return "网络扫描模块 - 使用nmap扫描目标设备开放端口和服务"
    
    def execute(self, params: Dict[str, Any]) -> bool:
        """
        执行网络扫描
        
        Args:
            params (Dict[str, Any]): 参数字典
                - target_ip: 目标IP地址
                - output_dir: 输出目录路径（可选）
                - xml_output: 是否输出XML格式结果，默认为False
                
        Returns:
            bool: 是否成功执行
        """
        target_ip = params.get('target_ip')
        xml_output = params.get('xml_output', False)
        
        if not target_ip:
            self.logger.error("缺少参数 'target_ip'")
            print("错误: 缺少参数 'target_ip'")
            return False
        
        self.logger.info(f"开始对目标 {target_ip} 进行网络扫描...")
        print(f"开始对目标 {target_ip} 进行网络扫描...")
        
        try:
            # 验证nmap是否可用
            self.logger.info("验证nmap是否已安装...")
            result = subprocess.run(['nmap', '--version'], 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True)
            if result.returncode != 0:
                self.logger.error(f"nmap未安装或不可用: {result.stderr}")
                print("错误: nmap未安装或不可用")
                return False
            else:
                self.logger.info("nmap已正确安装")
        except FileNotFoundError:
            self.logger.error("nmap未安装或不在系统PATH中")
            print("错误: nmap未安装或不在系统PATH中")
            return False
        
        # 执行全端口扫描
        self.logger.info("正在进行全端口扫描...")
        print("正在进行全端口扫描，请稍候...")
        
        # 构建nmap命令 - 只获取基本扫描结果
        cmd = ['nmap', '-T4', '-sS', '-sV', '-O', '-A', '-p-', target_ip]
        self.logger.info(f"执行命令: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                text=True)
        
        if result.returncode != 0:
            self.logger.error(f"扫描失败: {result.stderr}")
            print(f"扫描失败: {result.stderr}")
            return False
        
        # 获取项目目录
        self.logger.info("创建项目目录...")
        project_manager = ProjectManager(params.get('output_dir'))
        project_manager.create_project_directory()
        
        # 创建nmap_scan子目录，使用目标IP作为子目录名
        nmap_subdir_name = f"nmap_scan_{target_ip.replace('.', '_')}"
        project_manager.create_subdirectory([nmap_subdir_name])
        nmap_dir = project_manager.project_dir / nmap_subdir_name
        
        # 保存扫描结果
        scan_result = result.stdout
        
        # 保存普通文本格式（始终输出）
        txt_path = nmap_dir / f"nmap_scan_{target_ip}.txt"
        self.logger.info(f"保存文本格式扫描结果到: {txt_path}")
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(scan_result)
        
        # 可选：保存XML格式
        if xml_output:
            print("正在生成XML格式报告...")
            xml_cmd = ['nmap', '-T4', '-sS', '-sV', '-O', '-A', '-p-', '-oX', '-', target_ip]
            self.logger.info(f"执行XML格式扫描命令: {' '.join(xml_cmd)}")
            xml_result = subprocess.run(xml_cmd, 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        text=True)
            if xml_result.returncode == 0:
                xml_path = nmap_dir / f"nmap_scan_{target_ip}.xml"
                self.logger.info(f"保存XML格式扫描结果到: {xml_path}")
                with open(xml_path, 'w', encoding='utf-8') as f:
                    f.write(xml_result.stdout)
                print(f"XML格式扫描结果已保存到: {xml_path}")
            else:
                self.logger.warning("XML格式扫描失败")
                print("警告: XML格式扫描失败")
        
        self.logger.info(f"Nmap扫描完成，结果已保存到: {nmap_dir}")
        print(f"Nmap扫描完成，结果已保存到: {nmap_dir}")
        return True


class VulnerabilityScannerModule(BaseModule):
    """
    漏洞扫描模块（预留接口，待实现）
    """
    
    def __init__(self, debug_mode: bool = False):
        self.debug_mode = debug_mode
        self.logger = setup_logging('vulnerability_scanner', debug_mode)
    
    def name(self) -> str:
        return "vulnerability_scanner"
    
    def description(self) -> str:
        return "漏洞扫描模块 - 扫描目标设备可能存在的安全漏洞"
    
    def execute(self, params: Dict[str, Any]) -> bool:
        """
        执行漏洞扫描
        
        Args:
            params (Dict[str, Any]): 参数字典
            
        Returns:
            bool: 是否成功执行
        """
        self.logger.warning("漏洞扫描模块尚未实现")
        print("漏洞扫描模块尚未实现")
        return False