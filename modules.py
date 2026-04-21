#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自动化安全测试平台 - 功能模块实现

Author: Reid Xu
Date: 2026-03-08
"""

import os
import sys
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
                - certificate_type: 证书类型 ('rsa', 'ecc' 或 'auto'，默认为 'auto'）
                
        Returns:
            bool: 是否成功执行
        """
        pcap_file = params.get('pcap_file')
        tshark_path = params.get('tshark_path')  # 新增TShark路径参数
        generate_certificates = params.get('generate_certificates', False)  # 新增证书生成参数
        certificate_type = params.get('certificate_type', 'auto')  # 更新默认值为auto
        
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

        # 提取HTTP明文传输的URL
        http_urls = self._extract_http_urls(pcap_file, tshark_path)

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
                cert_type_display = certificate_type.upper() if certificate_type != 'auto' else '自动检测'
                self.logger.info(f"开始为每个域名生成{cert_type_display}证书文件...")
                print(f"开始为每个域名生成{cert_type_display}证书文件...")
                success = self._generate_certificates_for_domains(domain_port_map, project_manager.project_dir, certificate_type)
                if not success:
                    self.logger.warning("证书生成过程中出现错误，但TLS分析已完成")
                    print("警告: 证书生成过程中出现错误，但TLS分析已完成")

        # 处理HTTP明文URL结果
        if http_urls:
            self.logger.info(f"发现 {len(http_urls)} 个HTTP明文传输的URL")
            print(f"发现 {len(http_urls)} 个HTTP明文传输的URL:")
            for url in http_urls:
                print(f"  - {url}")
                self.logger.info(f"HTTP明文URL: {url}")

            # 创建http文件夹并保存URL信息
            # 使用项目目录而不是当前工作目录
            http_dir = project_manager.project_dir / "http"
            http_dir.mkdir(exist_ok=True)
            
            # 在文件名中添加时间戳
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            http_file = http_dir / f"http_urls_{timestamp}.txt"

            with open(http_file, 'w', encoding='utf-8') as f:
                f.write("HTTP明文传输URL列表\n")
                f.write("=" * 50 + "\n\n")
                for idx, url in enumerate(http_urls, 1):
                    f.write(f"{idx}. {url}\n")

            self.logger.info(f"HTTP明文URL已保存到: {http_file}")
            print(f"HTTP明文URL已保存到: {http_file}")
        else:
            self.logger.info("未发现HTTP明文传输的URL")
            print("未发现HTTP明文传输的URL")

        return True

    def _extract_http_urls(self, pcap_file_path: str, tshark_path: str = None) -> list:
        """
        从pcap文件中提取HTTP明文传输的URL

        Args:
            pcap_file_path (str): .pcapng文件路径
            tshark_path (str): TShark可执行文件路径（可选）

        Returns:
            list: 包含HTTP明文传输URL的列表
        """
        self.logger.info(f"开始提取HTTP明文URL，文件: {pcap_file_path}")
        http_urls = []

        try:
            # 使用tshark提取HTTP请求的Host和URI信息
            if tshark_path:
                self.logger.debug(f"使用自定义TShark路径: {tshark_path}")
                cap = pyshark.FileCapture(
                    pcap_file_path,
                    display_filter="http.request",
                    tshark_path=tshark_path,
                    keep_packets=True
                )
            else:
                cap = pyshark.FileCapture(pcap_file_path, display_filter="http.request")

            for packet in cap:
                try:
                    if hasattr(packet, 'http'):
                        # 提取Host字段
                        host = None
                        uri = None

                        if hasattr(packet.http, 'host'):
                            host = packet.http.host
                        if hasattr(packet.http, 'request_full_uri'):
                            uri = packet.http.request_full_uri
                        elif hasattr(packet.http, 'request_uri'):
                            uri = packet.http.request_uri

                        # 构建完整的URL
                        if host and uri:
                            # 判断是否是http://（明文）
                            if isinstance(uri, str) and uri.startswith('http'):
                                http_urls.append(uri)
                            else:
                                # 拼接Host和URI
                                url = f"http://{host}{uri}"
                                http_urls.append(url)
                        elif host and not uri:
                            http_urls.append(f"http://{host}")
                        elif uri and not host:
                            http_urls.append(str(uri))

                        self.logger.debug(f"提取到HTTP URL: {http_urls[-1] if http_urls else 'None'}")

                except AttributeError:
                    continue
                except Exception as e:
                    self.logger.error(f"处理HTTP包时出现错误: {e}")
                    continue

            cap.close()

            # 去重
            http_urls = list(dict.fromkeys(http_urls))

        except Exception as e:
            self.logger.error(f"读取PCAP文件提取HTTP URL时出现错误: {e}")

        self.logger.info(f"共提取到 {len(http_urls)} 个HTTP明文URL")
        return http_urls

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

    def _extract_cn_from_server_cert(self, domain: str, port: int) -> tuple:
        """
        从目标服务器的证书中提取Common Name (CN)和签名算法
        
        Args:
            domain (str): 目标域名
            port (int): TLS端口，默认8883
            
        Returns:
            tuple: (提取的Common Name, 证书签名算法类型('rsa'或'ecc'))
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
                return domain, 'rsa'  # 返回原始域名和默认rsa算法作为备选
            
            # 从输出中提取证书部分
            cert_output = result.stdout
            
            # 使用openssl x509解析证书并提取Subject和签名算法信息
            cmd2 = ['openssl', 'x509', '-noout', '-text']
            result2 = subprocess.run(cmd2,
                                   input=cert_output,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result2.returncode != 0:
                self.logger.warning(f"无法解析证书: {result2.stderr}")
                return domain, 'rsa'  # 返回原始域名和默认rsa算法作为备选
            
            # 从证书文本中提取Subject行和签名算法信息
            cert_text = result2.stdout
            subject_line = None
            sig_algo_line = None
            
            for line in cert_text.split('\n'):
                if 'Subject:' in line:
                    subject_line = line.strip()
                elif 'Signature Algorithm:' in line:
                    # 通常第一行 Signature Algorithm 是证书的签名算法
                    if sig_algo_line is None:
                        sig_algo_line = line.strip()
            
            # 确定证书类型
            cert_type = 'rsa'  # 默认为RSA
            if sig_algo_line:
                self.logger.info(f"服务器证书签名算法: {sig_algo_line}")
                # 检查是否是ECC算法 (ecdsa-with-SHA256 等)
                if 'ecdsa' in sig_algo_line.lower():
                    cert_type = 'ecc'
                    
            if not subject_line:
                self.logger.warning(f"未在证书中找到Subject字段")
                return domain, cert_type  # 返回原始域名和检测到的算法类型
            
            self.logger.debug(f"证书Subject: {subject_line}")
            
            # 提取CN字段
            # Subject格式: Subject: C=US, ST=State, L=City, O=Organization, OU=Unit, CN=*.example.com
            cn_start = subject_line.find('CN=')
            if cn_start == -1:
                self.logger.warning(f"未在Subject中找到CN字段")
                return domain, cert_type  # 返回原始域名和检测到的算法类型
            
            cn_part = subject_line[cn_start + 3:]  # 跳过'CN='
            # CN字段可能后面还有其他字段，用逗号分隔
            cn_end = cn_part.find(',')
            if cn_end != -1:
                cn_value = cn_part[:cn_end].strip()
            else:
                cn_value = cn_part.strip()
            
            if cn_value:
                self.logger.info(f"从服务器证书提取CN: {cn_value}, 类型: {cert_type}")
                return cn_value, cert_type
            else:
                self.logger.warning(f"提取的CN为空")
                return domain, cert_type
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"连接 {domain}:{port} 超时")
            return domain, 'rsa'
        except Exception as e:
            self.logger.error(f"提取证书CN时出现异常: {e}")
            return domain, 'rsa'

    def _generate_certificates_for_domains(self, domain_port_map: Dict[str, int], project_dir: Path, cert_type: str = 'auto') -> bool:
        """
        为每个域名生成证书、密钥和自签名文件
        
        Args:
            domain_port_map (Dict[str, int]): 域名到端口的映射字典
            project_dir (Path): 项目主目录路径
            cert_type (str): 证书类型 ('rsa', 'ecc' 或 'auto')
            
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
            
            try:
                # 从服务器证书中提取Common Name和算法类型
                extracted_cn, detected_type = self._extract_cn_from_server_cert(domain, port)
                
                # 确定证书类型
                actual_cert_type = cert_type
                if cert_type == 'auto':
                    actual_cert_type = detected_type
                    self.logger.info(f"自动检测到域名 {domain} 的证书类型为: {actual_cert_type.upper()}")
                    print(f"自动检测到域名 {domain} 的证书类型为: {actual_cert_type.upper()}")
                else:
                    self.logger.info(f"使用指定证书类型为域名 {domain}: {actual_cert_type.upper()}")
                    print(f"使用指定证书类型为域名 {domain}: {actual_cert_type.upper()}")
                
                self.logger.info(f"为域名 {domain} (端口: {port}) 生成{actual_cert_type.upper()}证书文件...")
                print(f"为域名 {domain} (端口: {port}) 生成{actual_cert_type.upper()}证书文件...")
                
                self.logger.info(f"使用提取的CN '{extracted_cn}' 生成证书")
                print(f"使用提取的CN '{extracted_cn}' 生成证书")
                
                # 根据证书类型决定生成方式
                if actual_cert_type.lower() == 'ecc':
                    success = self._generate_ecc_certificate(domain_dir, extracted_cn)
                else:  # 默认为RSA
                    success = self._generate_rsa_certificate(domain_dir, extracted_cn)
                
                if not success:
                    all_success = False
                    continue
                
                self.logger.info(f"成功为域名 {domain} 生成{actual_cert_type.upper()}证书文件")
                print(f"成功为域名 {domain} 生成{actual_cert_type.upper()}证书文件")
                
            except Exception as e:
                self.logger.error(f"生成证书时出现异常: {e}")
                print(f"生成证书时出现异常: {e}")
                all_success = False
        
        return all_success
    
    def _generate_rsa_certificate(self, domain_dir: Path, cn: str) -> bool:
        """生成RSA类型的证书"""
        try:
            # 1. 生成RSA私钥
            key_path = domain_dir / "server.key"
            cmd1 = ['openssl', 'genrsa', '-out', str(key_path), '2048']
            self.logger.debug(f"执行命令: {' '.join(cmd1)}")
            result1 = subprocess.run(cmd1, 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True)
            if result1.returncode != 0:
                self.logger.error(f"生成RSA私钥失败: {result1.stderr}")
                print(f"生成RSA私钥失败: {result1.stderr}")
                return False
            
            # 2. 生成证书请求文件（CSR）
            csr_path = domain_dir / "server.csr"
            input_data = f"11\n11\n11\n11\n11\n{cn}\n1111\n1111\n1111\n"
            
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
                return False
            
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
                return False
            
            return True
        except Exception as e:
            self.logger.error(f"生成RSA证书时出现异常: {e}")
            return False
    
    def _generate_ecc_certificate(self, domain_dir: Path, cn: str) -> bool:
        """生成ECC类型的证书"""
        try:
            # 1. 生成椭圆曲线参数和私钥
            key_path = domain_dir / "server.key"
            # 使用prime256v1曲线，对应ECDSA-with-SHA256
            cmd1 = ['openssl', 'ecparam', '-genkey', '-name', 'prime256v1', '-out', str(key_path)]
            self.logger.debug(f"执行命令: {' '.join(cmd1)}")
            result1 = subprocess.run(cmd1, 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True)
            if result1.returncode != 0:
                self.logger.error(f"生成ECC私钥失败: {result1.stderr}")
                print(f"生成ECC私钥失败: {result1.stderr}")
                return False
            
            # 2. 生成证书请求文件（CSR）
            csr_path = domain_dir / "server.csr"
            input_data = f"11\n11\n11\n11\n11\n{cn}\n1111\n1111\n1111\n"
            
            cmd2 = ['openssl', 'req', '-new', '-key', str(key_path), '-out', str(csr_path)]
            self.logger.debug(f"执行命令: {' '.join(cmd2)}")
            result2 = subprocess.run(cmd2, 
                                    input=input_data,
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True)
            if result2.returncode != 0:
                self.logger.error(f"生成ECC CSR失败: {result2.stderr}")
                print(f"生成ECC CSR失败: {result2.stderr}")
                return False
            
            # 3. 生成自签名证书，指定使用SHA256算法
            crt_path = domain_dir / "server.crt"
            cmd3 = ['openssl', 'x509', '-req', '-in', str(csr_path), '-signkey', str(key_path), '-out', str(crt_path), '-days', '365', '-sha256']
            self.logger.debug(f"执行命令: {' '.join(cmd3)}")
            result3 = subprocess.run(cmd3, 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True)
            if result3.returncode != 0:
                self.logger.error(f"生成ECC自签名证书失败: {result3.stderr}")
                print(f"生成ECC自签名证书失败: {result3.stderr}")
                return False
            
            return True
        except Exception as e:
            self.logger.error(f"生成ECC证书时出现异常: {e}")
            return False


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
                - scan_mode: 扫描模式 ('tcp' 或 'udp'，默认为 'tcp')
                - lite: 是否使用精简模式 (bool，默认为False)
                - output_dir: 输出目录路径（可选）
                - xml_output: 是否输出XML格式结果，默认为False
                
        Returns:
            bool: 是否成功执行
        """
        target_ip = params.get('target_ip')
        scan_mode = params.get('scan_mode', 'tcp').lower()  # 默认为TCP模式
        lite_mode = params.get('lite', False)  # 默认为详细模式
        xml_output = params.get('xml_output', False)
        
        if not target_ip:
            self.logger.error("缺少参数 'target_ip'")
            print("错误: 缺少参数 'target_ip'")
            return False
        
        if scan_mode not in ['tcp', 'udp']:
            self.logger.error("扫描模式必须是 'tcp' 或 'udp'")
            print("错误: 扫描模式必须是 'tcp' 或 'udp'")
            return False
        
        scan_type = "精简" if lite_mode else "详细"
        self.logger.info(f"开始对目标 {target_ip} 进行{scan_type}{scan_mode.upper()}模式网络扫描...")
        print(f"开始对目标 {target_ip} 进行{scan_type}{scan_mode.upper()}模式网络扫描...")
        
        try:
            # 验证nmap是否可用
            self.logger.info("验证nmap是否已安装...")
            # 在Windows上隐藏子进程窗口
            if sys.platform == "win32":
                # 使用CREATE_NO_WINDOW标志隐藏窗口
                import subprocess
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                result = subprocess.run(['nmap', '--version'], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        text=True,
                                        startupinfo=startupinfo)
            else:
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
        
        # 根据扫描模式和精简模式构建命令
        if scan_mode == 'tcp':
            if lite_mode:
                # 精简TCP模式: nmap -T4 -sS -sV -p- [target IP]
                cmd = ['nmap', '-T4', '-sS', '-sV', '-p-', target_ip]
                print("正在进行精简TCP全端口扫描，请稍候...")
            else:
                # 详细TCP模式: nmap -T4 -sS -sV -O -A -p- [target IP]
                cmd = ['nmap', '-T4', '-sS', '-sV', '-O', '-A', '-p-', target_ip]
                print("正在进行详细TCP全端口扫描，请稍候...")
        else:  # UDP模式
            if lite_mode:
                # 精简UDP模式: nmap -sU -T4 -sV -Pn [target IP]
                cmd = ['nmap', '-sU', '-T4', '-sV', '-Pn', target_ip]
                print("正在进行精简UDP服务扫描，请稍候...")
            else:
                # 详细UDP模式: nmap -sU -T4 -A -v -Pn [target IP]
                cmd = ['nmap', '-sU', '-T4', '-A', '-v', '-Pn', target_ip]
                print("正在进行详细UDP服务扫描，请稍候...UDP扫描通常比较耗时...")
        
        # 执行扫描
        self.logger.info(f"执行{scan_type}{scan_mode.upper()}扫描...")
        self.logger.info(f"执行命令: {' '.join(cmd)}")
        
        # 在Windows上隐藏子进程窗口
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            result = subprocess.run(cmd, 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True,
                                    startupinfo=startupinfo)
        else:
            result = subprocess.run(cmd, 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True)
        
        if result.returncode != 0:
            self.logger.error(f"{scan_type}{scan_mode.upper()}扫描失败: {result.stderr}")
            print(f"{scan_type}{scan_mode.upper()}扫描失败: {result.stderr}")
            return False
        
        # 获取项目目录
        self.logger.info("创建项目目录...")
        project_manager = ProjectManager(params.get('output_dir'))
        project_manager.create_project_directory()
        
        # 创建nmap_scan子目录，使用目标IP和扫描模式作为子目录名
        mode_prefix = "lite_" if lite_mode else ""
        nmap_subdir_name = f"nmap_{mode_prefix}{scan_mode}_scan_{target_ip.replace('.', '_')}"
        project_manager.create_subdirectory([nmap_subdir_name])
        nmap_dir = project_manager.project_dir / nmap_subdir_name
        
        # 保存扫描结果
        scan_result = result.stdout
        
        # 保存普通文本格式（始终输出）
        txt_path = nmap_dir / f"nmap_{mode_prefix}{scan_mode}_scan_{target_ip}.txt"
        self.logger.info(f"保存文本格式扫描结果到: {txt_path}")
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(scan_result)
        
        # 可选：保存XML格式
        if xml_output:
            print("正在生成XML格式报告...")
            
            # 根据扫描模式和精简模式构建XML输出命令
            if scan_mode == 'tcp':
                if lite_mode:
                    xml_cmd = ['nmap', '-T4', '-sS', '-sV', '-p-', '-oX', '-', target_ip]
                else:
                    xml_cmd = ['nmap', '-T4', '-sS', '-sV', '-O', '-A', '-p-', '-oX', '-', target_ip]
            else:  # UDP
                if lite_mode:
                    xml_cmd = ['nmap', '-sU', '-T4', '-sV', '-Pn', '-oX', '-', target_ip]
                else:
                    xml_cmd = ['nmap', '-sU', '-T4', '-A', '-v', '-Pn', '-oX', '-', target_ip]
                
            self.logger.info(f"执行XML格式{scan_type}{scan_mode.upper()}扫描命令: {' '.join(xml_cmd)}")
            # 在Windows上隐藏子进程窗口
            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                xml_result = subprocess.run(xml_cmd, 
                                            stdout=subprocess.PIPE, 
                                            stderr=subprocess.PIPE, 
                                            text=True,
                                            startupinfo=startupinfo)
            else:
                xml_result = subprocess.run(xml_cmd, 
                                            stdout=subprocess.PIPE, 
                                            stderr=subprocess.PIPE, 
                                            text=True)
            if xml_result.returncode == 0:
                xml_path = nmap_dir / f"nmap_{mode_prefix}{scan_mode}_scan_{target_ip}.xml"
                self.logger.info(f"保存XML格式扫描结果到: {xml_path}")
                with open(xml_path, 'w', encoding='utf-8') as f:
                    f.write(xml_result.stdout)
                print(f"XML格式扫描结果已保存到: {xml_path}")
            else:
                self.logger.warning("XML格式扫描失败")
                print("警告: XML格式扫描失败")
        
        self.logger.info(f"Nmap {scan_type}{scan_mode.upper()}扫描完成，结果已保存到: {nmap_dir}")
        print(f"Nmap {scan_type}{scan_mode.upper()}扫描完成，结果已保存到: {nmap_dir}")
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