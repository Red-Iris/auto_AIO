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
#from typing import Dict, Any, Set
from pathlib import Path
from core import BaseModule, ProjectManager
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any,Set
import ipaddress
import re


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


@dataclass
class CertificateProfile:
    key_type: str = "rsa"                  # "rsa" or "ec"
    rsa_bits: int = 2048                   # 2048 / 3072
    ec_curve: str = "P-256"                # P-256 / P-384
    digest: str = "sha256"                 # sha256 / sha384

    cn: str = "localhost"
    subject: str = "/CN=localhost"

    san_dns: List[str] = field(default_factory=list)
    san_ip: List[str] = field(default_factory=list)

    key_usage: List[str] = field(default_factory=lambda: ["digitalSignature", "keyEncipherment"])
    extended_key_usage: List[str] = field(default_factory=lambda: ["serverAuth"])
    basic_constraints: Optional[str] = "critical,CA:FALSE"


class TLSAnalyzerModule(BaseModule):
    """
    TLS域名分析模块
    从pcap文件中提取TLS握手包中的服务器名称，并可按证书画像生成自签名证书
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
        tshark_path = params.get('tshark_path')
        generate_certificates = params.get('generate_certificates', False)
        certificate_type = params.get('certificate_type', 'auto')

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

        project_manager = None
        project_dir = None

        # 只要有 TLS 域名或 HTTP URL，就创建项目目录
        if domain_port_map or http_urls:
            project_manager = ProjectManager(params.get('output_dir'))
            project_dir = project_manager.create_project_directory()

        if not domain_port_map:
            self.logger.warning("未发现TLS握手包中的域名信息")
            print("未发现TLS握手包中的域名信息")
        else:
            domains = set(domain_port_map.keys())
            project_manager.create_subdirectory(list(domains))

            self.logger.info(f"发现 {len(domains)} 个唯一的域名: {domains}")
            print(f"发现 {len(domains)} 个唯一的域名:")
            for domain in domains:
                print(f"  - {domain} (端口: {domain_port_map[domain]})")

            self.logger.info(f"项目目录结构已创建完成: {project_dir}")
            print("项目目录结构创建完成")

            if generate_certificates:
                cert_type_display = certificate_type.upper() if certificate_type != 'auto' else '自动检测'
                self.logger.info(f"开始为每个域名生成{cert_type_display}证书文件...")
                print(f"开始为每个域名生成{cert_type_display}证书文件...")

                success = self._generate_certificates_for_domains(
                    domain_port_map,
                    project_manager.project_dir,
                    certificate_type
                )
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

            http_dir = project_manager.project_dir / "http"
            http_dir.mkdir(exist_ok=True)

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
        """
        self.logger.info(f"开始提取HTTP明文URL，文件: {pcap_file_path}")
        http_urls = []

        try:
            if tshark_path:
                self.logger.debug(f"使用自定义TShark路径: {tshark_path}")
                cap = pyshark.FileCapture(
                    pcap_file_path,
                    display_filter="http.request",
                    tshark_path=tshark_path,
                    keep_packets=True
                )
            else:
                cap = pyshark.FileCapture(
                    pcap_file_path,
                    display_filter="http.request",
                    keep_packets=True
                )

            for packet in cap:
                try:
                    if hasattr(packet, 'http'):
                        host = None
                        uri = None

                        if hasattr(packet.http, 'host'):
                            host = packet.http.host
                        if hasattr(packet.http, 'request_full_uri'):
                            uri = packet.http.request_full_uri
                        elif hasattr(packet.http, 'request_uri'):
                            uri = packet.http.request_uri

                        if host and uri:
                            if isinstance(uri, str) and uri.startswith('http'):
                                http_urls.append(uri)
                            else:
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
            http_urls = list(dict.fromkeys(http_urls))

        except Exception as e:
            self.logger.error(f"读取PCAP文件提取HTTP URL时出现错误: {e}")

        self.logger.info(f"共提取到 {len(http_urls)} 个HTTP明文URL")
        return http_urls
    
    def _get_cert_extension_text(self, leaf_pem: str, ext_name: str) -> str:
        """
        直接用 openssl x509 -ext 读取单个扩展，避免从 -text 整段文本里手撕解析
        """
        result = self._run_cmd(
            ['openssl', 'x509', '-noout', '-ext', ext_name],
            input_text=leaf_pem
        )
        if result.returncode != 0:
            return ""

        text = result.stdout.strip()
        if not text:
            return ""

        lines = text.splitlines()

        # 常见输出形态：
        # X509v3 Subject Alternative Name:
        #     DNS:example.com, DNS:www.example.com
        #
        # 或者：
        # subjectAltName=DNS:example.com
        #
        # 统一把标题去掉，只保留值
        if len(lines) >= 2 and lines[0].strip().endswith(":"):
            return " ".join(line.strip() for line in lines[1:]).strip()

        # 兼容 "name=value" 形式
        if "=" in text:
            return text.split("=", 1)[1].strip()

        return text

    def _escape_subj_value(self, value: str) -> str:
        """
        生成 -subj 时对值做最基本转义
        """
        if value is None:
            return ""
        return (
            str(value)
            .replace("\\", "\\\\")
            .replace("/", r"\/")
        )

    def _build_fixed_subject(self, cn: str) -> str:
        """
        始终使用你原来那套固定 Subject 模板，只把 CN 动态替换进去
        """
        cn = self._escape_subj_value(cn)
        return (
            f"/C=XX"
            f"/ST=TestLand"
            f"/L=TestCity"
            f"/O=TestOrg"
            f"/OU=TestUnit"
            f"/CN={cn}"
            f"/emailAddress=test@example.com"
        )

    def _extract_tls_domains_and_ports(self, pcap_file_path: str, tshark_path: str = None) -> Dict[str, int]:
        """
        从pcap文件中提取TLS握手包中的服务器名称和对应的端口
        """
        self.logger.info(f"开始提取TLS域名和端口，文件: {pcap_file_path}")
        domain_port_map = {}

        try:
            if tshark_path:
                self.logger.debug(f"使用自定义TShark路径: {tshark_path}")
                cap = pyshark.FileCapture(
                    pcap_file_path,
                    display_filter="tls.handshake.extensions_server_name",
                    tshark_path=tshark_path,
                    keep_packets=True
                )
            else:
                cap = pyshark.FileCapture(
                    pcap_file_path,
                    display_filter="tls.handshake.extensions_server_name",
                    keep_packets=True
                )

            for packet in cap:
                try:
                    if hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake_extensions_server_name'):
                        server_name = packet.tls.handshake_extensions_server_name
                        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport'):
                            dst_port = int(packet.tcp.dstport)
                            domain_port_map[server_name] = dst_port
                            self.logger.debug(f"提取到域名: {server_name}, 端口: {dst_port}")
                        else:
                            domain_port_map[server_name] = 8883
                            self.logger.debug(f"提取到域名: {server_name}, 端口未知，使用默认8883")
                except AttributeError:
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

    # =========================
    # 通用命令/解析辅助函数
    # =========================

    def _run_cmd(self, cmd: list, input_text: str = None, timeout: int = 30) -> subprocess.CompletedProcess:
        self.logger.debug(f"执行命令: {' '.join(cmd)}")
        return subprocess.run(
            cmd,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )

    def _is_ip_address(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _extract_first_pem_certificate(self, text: str) -> Optional[str]:
        m = re.search(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            text,
            re.DOTALL
        )
        return m.group(0) if m else None

    def _normalize_digest(self, sig_alg: str) -> str:
        s = (sig_alg or "").lower()
        if "sha384" in s:
            return "sha384"
        return "sha256"

    def _normalize_rsa_bits(self, bits: Optional[int]) -> int:
        if bits == 3072:
            return 3072
        return 2048

    def _normalize_ec_curve(self, curve_text: str) -> str:
        s = (curve_text or "").lower()
        if "p-384" in s or "secp384r1" in s or "384" in s:
            return "P-384"
        return "P-256"

    def _openssl_curve_name(self, ec_curve: str) -> str:
        if ec_curve == "P-384":
            return "secp384r1"
        return "prime256v1"

    def _extract_x509v3_value(self, cert_text: str, ext_name: str) -> str:
        """
        更稳地提取某个扩展的值：
        - 兼容 'X509v3 Subject Alternative Name:'
        - 兼容后续出现 'CT Precertificate SCTs:' 这类非 X509v3 前缀扩展
        - 只收集真正属于该扩展的缩进行
        """
        lines = cert_text.splitlines()
        capture = False
        values = []

        # 例如: "            X509v3 Subject Alternative Name:"
        target_header = re.compile(
            rf"^\s*X509v3 {re.escape(ext_name)}:(?:\s+critical)?\s*$"
        )

        # 任意扩展标题：
        #   "            X509v3 Key Usage:"
        #   "            CT Precertificate SCTs:"
        #   "            Authority Information Access:"
        any_ext_header = re.compile(
            r"^\s{4,}[A-Za-z0-9][A-Za-z0-9 .\-/()]*:\s*$"
        )

        for line in lines:
            if not capture:
                if target_header.match(line):
                    capture = True
                continue

            # 已进入目标扩展值区
            # 1) 新扩展标题开始 -> 停
            if any_ext_header.match(line):
                break

            # 2) 空行跳过
            if not line.strip():
                continue

            # 3) 只有缩进行才算值
            if line.startswith(" "):
                values.append(line.strip())
            else:
                break

        return " ".join(values).strip()

    def _normalize_basic_constraints(self, bc_text: str) -> str:
        """
        只保留 basicConstraints 中真正可用于 -addext 的部分。
        目标是生成叶子证书时保持稳定，不盲目复制杂项内容。
        """
        s = (bc_text or "").strip()

        ca_true = re.search(r'\bCA\s*:\s*TRUE\b', s, re.IGNORECASE)
        ca_false = re.search(r'\bCA\s*:\s*FALSE\b', s, re.IGNORECASE)
        pathlen = re.search(r'\bpathlen\s*:\s*(\d+)\b', s, re.IGNORECASE)

        parts = ["critical"]

        if ca_true:
            parts.append("CA:TRUE")
        else:
            # 默认按服务端叶子证书处理
            parts.append("CA:FALSE")

        if pathlen and ca_true:
            parts.append(f"pathlen:{pathlen.group(1)}")

        return ",".join(parts)

    def _parse_subject_to_subj_arg(self, subject_text: Optional[str], fallback_cn: str) -> str:
        """
        将 openssl 输出的 Subject 文本转成 -subj 可接受的 /C=.../ST=.../CN=... 格式
        """
        if not subject_text:
            return f"/CN={fallback_cn}"

        subject_text = subject_text.strip()
        subject_text = re.sub(r"^(Subject:|subject=)\s*", "", subject_text)

        parts = [p.strip() for p in re.split(r"(?<!\\),\s*", subject_text) if "=" in p]
        if not parts:
            return f"/CN={fallback_cn}"

        subj = ""
        for part in parts:
            k, v = part.split("=", 1)
            k = k.strip()
            v = v.strip()
            if not k or not v:
                continue
            v = v.replace("/", r"\/")
            subj += f"/{k}={v}"

        return subj or f"/CN={fallback_cn}"

    def _extract_cn_from_subject(self, subject_text: Optional[str], fallback: str) -> str:
        if not subject_text:
            return fallback

        subject_text = re.sub(r"^(Subject:|subject=)\s*", "", subject_text).strip()
        m = re.search(r"(?:^|,\s*)CN\s*=\s*([^,]+)", subject_text)
        if m:
            return m.group(1).strip()
        return fallback

    def _parse_san_lists(self, san_text: str) -> Tuple[List[str], List[str]]:
        dns_list = []
        ip_list = []

        if not san_text:
            return dns_list, ip_list

        for part in [x.strip() for x in san_text.split(",")]:
            upper = part.upper()

            if upper.startswith("DNS:"):
                value = part.split(":", 1)[1].strip()
                if value:
                    dns_list.append(value)
                continue

            if upper.startswith("IP ADDRESS:") or upper.startswith("IP:"):
                value = part.split(":", 1)[1].strip()

                # 只取第一个连续非空白 token，避免把 "Signature Algorithm: ..." 吞进去
                value = value.split()[0]

                # 必须真的是合法 IP 才收
                try:
                    ipaddress.ip_address(value)
                    ip_list.append(value)
                except ValueError:
                    pass

        return list(dict.fromkeys(dns_list)), list(dict.fromkeys(ip_list))

    def _parse_usage_list(self, usage_text: str) -> List[str]:
        if not usage_text:
            return []
        return [x.strip() for x in usage_text.split(",") if x.strip()]

    def _normalize_key_usage_values(self, values: List[str]) -> List[str]:
        mapping = {
            "digital signature": "digitalSignature",
            "non repudiation": "nonRepudiation",
            "content commitment": "nonRepudiation",
            "key encipherment": "keyEncipherment",
            "data encipherment": "dataEncipherment",
            "key agreement": "keyAgreement",
            "certificate sign": "keyCertSign",
            "crl sign": "cRLSign",
            "encipher only": "encipherOnly",
            "decipher only": "decipherOnly",
        }
        normalized = []
        for item in values:
            k = item.strip().lower()
            if k in mapping:
                normalized.append(mapping[k])
            elif item in mapping.values():
                normalized.append(item)

        # 去重保序
        return list(dict.fromkeys(normalized))

    def _normalize_eku_values(self, values: List[str]) -> List[str]:
        mapping = {
            "tls web server authentication": "serverAuth",
            "tls web client authentication": "clientAuth",
            "code signing": "codeSigning",
            "e-mail protection": "emailProtection",
            "time stamping": "timeStamping",
            "ocsp signing": "OCSPSigning",
        }
        normalized = []
        for item in values:
            k = item.strip().lower()
            if k in mapping:
                normalized.append(mapping[k])
            elif item in mapping.values():
                normalized.append(item)

        return list(dict.fromkeys(normalized))

    def _default_key_usage_for_profile(self, key_type: str) -> List[str]:
        if key_type == "ec":
            return ["digitalSignature"]
        return ["digitalSignature", "keyEncipherment"]

    def _profile_summary(self, p: CertificateProfile) -> str:
        if p.key_type == "rsa":
            key_desc = f"RSA-{p.rsa_bits}"
        else:
            key_desc = f"EC-{p.ec_curve}"

        san_parts = []
        if p.san_dns:
            san_parts.append("DNS=" + ",".join(p.san_dns))
        if p.san_ip:
            san_parts.append("IP=" + ",".join(p.san_ip))

        return f"{key_desc}, {p.digest.upper()}, CN={p.cn}, SAN[{'; '.join(san_parts) if san_parts else 'none'}]"

    def _default_profile_for_target(self, host: str) -> CertificateProfile:
        is_ip = self._is_ip_address(host)
        profile = CertificateProfile(
            key_type="rsa",
            rsa_bits=2048,
            digest="sha256",
            cn=host,
            subject=self._build_fixed_subject(host),
            key_usage=["digitalSignature", "keyEncipherment"],
            extended_key_usage=["serverAuth"],
            basic_constraints="critical,CA:FALSE"
        )
        if is_ip:
            profile.san_ip = [host]
        else:
            profile.san_dns = [host]
        return profile

    # =========================
    # 证书画像提取
    # =========================

    def _extract_server_cert_profile(self, domain: str, port: int) -> CertificateProfile:
        """
        从目标服务器证书提取完整画像：
        - key_type: rsa / ec
        - rsa_bits: 2048 / 3072
        - ec_curve: P-256 / P-384
        - digest: sha256 / sha384
        - subject / cn
        - SAN (DNS / IP)
        """
        profile = self._default_profile_for_target(domain)

        try:
            cmd = ['openssl', 's_client', '-connect', f'{domain}:{port}', '-showcerts']
            if not self._is_ip_address(domain):
                cmd.extend(['-servername', domain])

            result = self._run_cmd(cmd, input_text="", timeout=30)
            if result.returncode != 0:
                self.logger.warning(f"无法连接到 {domain}:{port} 获取证书: {result.stderr}")
                return profile

            leaf_pem = self._extract_first_pem_certificate(result.stdout)
            if not leaf_pem:
                self.logger.warning(f"未能从 {domain}:{port} 提取叶子证书")
                return profile

            result_text = self._run_cmd(['openssl', 'x509', '-noout', '-text'], input_text=leaf_pem)
            if result_text.returncode != 0:
                self.logger.warning(f"无法解析证书文本: {result_text.stderr}")
                return profile
            cert_text = result_text.stdout

            result_subject = self._run_cmd(
                ['openssl', 'x509', '-noout', '-subject', '-nameopt', 'RFC2253'],
                input_text=leaf_pem
            )
            subject_text = result_subject.stdout.strip() if result_subject.returncode == 0 else None

            sig_alg = None
            for line in cert_text.splitlines():
                if 'Signature Algorithm:' in line:
                    sig_alg = line.split(':', 1)[1].strip()
                    break
            profile.digest = self._normalize_digest(sig_alg or "")

            m_pubalg = re.search(r'Public Key Algorithm:\s*([^\n]+)', cert_text)
            pub_alg = m_pubalg.group(1).strip() if m_pubalg else ""

            if 'ec' in pub_alg.lower() or (sig_alg and 'ecdsa' in sig_alg.lower()):
                profile.key_type = 'ec'
            else:
                profile.key_type = 'rsa'

            m_bits = re.search(r'Public-Key:\s*\((\d+)\s+bit\)', cert_text)
            if m_bits:
                bits = int(m_bits.group(1))
                if profile.key_type == "rsa":
                    profile.rsa_bits = self._normalize_rsa_bits(bits)

            m_curve = re.search(r'NIST CURVE:\s*([^\n]+)', cert_text)
            curve_text = m_curve.group(1).strip() if m_curve else ""
            if not curve_text:
                m_oid = re.search(r'ASN1 OID:\s*([^\n]+)', cert_text)
                curve_text = m_oid.group(1).strip() if m_oid else ""
            if profile.key_type == "ec":
                profile.ec_curve = self._normalize_ec_curve(curve_text)

            profile.cn = self._extract_cn_from_subject(subject_text, fallback=domain)
            profile.subject = self._build_fixed_subject(profile.cn)

            san_text = self._get_cert_extension_text(leaf_pem, "subjectAltName")
            san_dns, san_ip = self._parse_san_lists(san_text)
            profile.san_dns = san_dns
            profile.san_ip = san_ip

            if not profile.san_dns and not profile.san_ip:
                if self._is_ip_address(profile.cn):
                    profile.san_ip = [profile.cn]
                else:
                    profile.san_dns = [profile.cn]

            key_usage_text = self._get_cert_extension_text(leaf_pem, "keyUsage")
            eku_text = self._get_cert_extension_text(leaf_pem, "extendedKeyUsage")
            bc_text = self._get_cert_extension_text(leaf_pem, "basicConstraints")

            parsed_ku = self._normalize_key_usage_values(self._parse_usage_list(key_usage_text))
            parsed_eku = self._normalize_eku_values(self._parse_usage_list(eku_text))

            if parsed_ku:
                profile.key_usage = parsed_ku
            else:
                profile.key_usage = self._default_key_usage_for_profile(profile.key_type)

            if parsed_eku:
                profile.extended_key_usage = parsed_eku
            else:
                profile.extended_key_usage = ["serverAuth"]

            if bc_text:
                profile.basic_constraints = self._normalize_basic_constraints(bc_text)
            else:
                profile.basic_constraints = "critical,CA:FALSE"

            self.logger.info(f"提取证书画像成功: {self._profile_summary(profile)}")
            return profile

        except subprocess.TimeoutExpired:
            self.logger.warning(f"连接 {domain}:{port} 超时，使用默认画像")
            return profile
        except Exception as e:
            self.logger.error(f"提取证书画像时出现异常: {e}")
            return profile

    def _extract_cn_from_server_cert(self, domain: str, port: int) -> tuple:
        """
        兼容旧接口：返回 (CN, 证书类型'rsa'/'ecc')
        """
        profile = self._extract_server_cert_profile(domain, port)
        cert_type = 'ecc' if profile.key_type == 'ec' else 'rsa'
        return profile.cn, cert_type

    # =========================
    # 证书生成
    # =========================

    def _build_addext_args(self, profile: CertificateProfile) -> List[str]:
        args = []

        # 1. basicConstraints
        bc = (profile.basic_constraints or "").strip()
        if bc:
            # 兜底清洗，防止把额外内容带进去
            bc = self._normalize_basic_constraints(bc)
            args += ['-addext', f'basicConstraints={bc}']

        # 2. keyUsage
        ku = self._normalize_key_usage_values(profile.key_usage or [])
        if ku:
            args += ['-addext', f"keyUsage={','.join(ku)}"]

        # 3. extendedKeyUsage
        eku = self._normalize_eku_values(profile.extended_key_usage or [])
        if eku:
            args += ['-addext', f"extendedKeyUsage={','.join(eku)}"]

        # 4. subjectAltName
        san_items = []
        for d in profile.san_dns or []:
            d = d.strip()
            if d:
                san_items.append(f"DNS:{d}")
        for ip in profile.san_ip or []:
            ip = ip.strip()
            if ip:
                san_items.append(f"IP:{ip}")

        if san_items:
            args += ['-addext', f"subjectAltName={','.join(san_items)}"]

        return args

    def _generate_certificate_from_profile(self, domain_dir: Path, profile: CertificateProfile) -> bool:
        """
        根据 CertificateProfile 统一生成：
        - server.key
        - server.csr
        - server.crt
        """
        try:
            key_path = domain_dir / "server.key"
            csr_path = domain_dir / "server.csr"
            crt_path = domain_dir / "server.crt"

            # 1) 生成私钥
            if profile.key_type == "rsa":
                cmd_key = [
                    'openssl', 'genpkey',
                    '-algorithm', 'RSA',
                    '-out', str(key_path),
                    '-pkeyopt', f'rsa_keygen_bits:{profile.rsa_bits}'
                ]
            else:
                cmd_key = [
                    'openssl', 'genpkey',
                    '-algorithm', 'EC',
                    '-out', str(key_path),
                    '-pkeyopt', f'ec_paramgen_curve:{self._openssl_curve_name(profile.ec_curve)}',
                    '-pkeyopt', 'ec_param_enc:named_curve'
                ]

            result_key = self._run_cmd(cmd_key)
            if result_key.returncode != 0:
                self.logger.error(f"生成私钥失败: {result_key.stderr}")
                print(f"生成私钥失败: {result_key.stderr}")
                return False

            # 2) 生成 CSR（保留与旧项目兼容的 server.csr）
            cmd_csr = [
                'openssl', 'req',
                '-new',
                '-key', str(key_path),
                '-out', str(csr_path),
                f'-{profile.digest}',
                '-subj', profile.subject
            ] + self._build_addext_args(profile)

            result_csr = self._run_cmd(cmd_csr)
            if result_csr.returncode != 0:
                self.logger.error(f"生成CSR失败: {result_csr.stderr}")
                print(f"生成CSR失败: {result_csr.stderr}")
                return False

            # 3) 直接按同样画像生成自签名证书
            cmd_crt = [
                'openssl', 'req',
                '-new',
                '-x509',
                '-key', str(key_path),
                '-out', str(crt_path),
                '-days', '365',
                f'-{profile.digest}',
                '-subj', profile.subject
            ] + self._build_addext_args(profile)

            result_crt = self._run_cmd(cmd_crt)
            if result_crt.returncode != 0:
                self.logger.error(f"生成自签名证书失败: {result_crt.stderr}")
                print(f"生成自签名证书失败: {result_crt.stderr}")
                return False

            return True

        except Exception as e:
            self.logger.error(f"根据画像生成证书时出现异常: {e}")
            return False

    def _apply_cert_type_override(self, profile: CertificateProfile, cert_type: str) -> CertificateProfile:
        """
        保留旧参数风格：
        - auto: 按提取画像
        - rsa : 强制改为 RSA
        - ecc : 强制改为 EC
        """
        cert_type = (cert_type or "auto").lower()

        if cert_type == "rsa":
            profile.key_type = "rsa"
            profile.rsa_bits = self._normalize_rsa_bits(profile.rsa_bits)
            if not profile.key_usage:
                profile.key_usage = ["digitalSignature", "keyEncipherment"]
        elif cert_type in ("ecc", "ec"):
            profile.key_type = "ec"
            profile.ec_curve = self._normalize_ec_curve(profile.ec_curve)
            if not profile.key_usage or profile.key_usage == ["digitalSignature", "keyEncipherment"]:
                profile.key_usage = ["digitalSignature"]

        profile.digest = "sha384" if profile.digest == "sha384" else "sha256"
        return profile

    def _generate_certificates_for_domains(self, domain_port_map: Dict[str, int], project_dir: Path, cert_type: str = 'auto') -> bool:
        """
        为每个域名生成证书、密钥和自签名文件
        """
        try:
            result = self._run_cmd(['openssl', 'version'])
            if result.returncode != 0:
                self.logger.error(f"OpenSSL未安装或不可用: {result.stderr}")
                print("错误: OpenSSL未安装或不可用，无法生成证书文件")
                return False
            else:
                self.logger.info(f"OpenSSL已正确安装: {result.stdout.strip()}")
        except FileNotFoundError:
            self.logger.error("OpenSSL未安装或不在系统PATH中")
            print("错误: OpenSSL未安装或不在系统PATH中，无法生成证书文件")
            return False

        all_success = True

        for domain, port in domain_port_map.items():
            safe_domain = str(domain).replace('/', '_').replace('\\', '_').replace('*', '_').replace('?', '_').replace('"', '_').replace('<', '_').replace('>', '_').replace('|', '_')
            domain_dir = project_dir / safe_domain

            if not domain_dir.exists():
                self.logger.warning(f"域名目录不存在，跳过证书生成: {domain_dir}")
                continue

            try:
                profile = self._extract_server_cert_profile(domain, port)
                profile = self._apply_cert_type_override(profile, cert_type)

                self.logger.info(f"为域名 {domain} (端口: {port}) 使用画像: {self._profile_summary(profile)}")
                print(f"为域名 {domain} (端口: {port}) 使用画像: {self._profile_summary(profile)}")

                success = self._generate_certificate_from_profile(domain_dir, profile)
                if not success:
                    all_success = False
                    continue

                self.logger.info(f"成功为域名 {domain} 生成证书文件")
                print(f"成功为域名 {domain} 生成证书文件")

            except Exception as e:
                self.logger.error(f"生成证书时出现异常: {e}")
                print(f"生成证书时出现异常: {e}")
                all_success = False

        return all_success

    # =========================
    # 旧接口兼容包装
    # =========================

    # def _generate_rsa_certificate(self, domain_dir: Path, cn: str) -> bool:
    #     """
    #     兼容旧接口：固定生成 RSA-2048 / SHA256
    #     """
    #     profile = CertificateProfile(
    #         key_type="rsa",
    #         rsa_bits=2048,
    #         digest="sha256",
    #         cn=cn,
    #         subject=f"/CN={cn}",
    #         san_dns=[] if self._is_ip_address(cn) else [cn],
    #         san_ip=[cn] if self._is_ip_address(cn) else [],
    #         key_usage=["digitalSignature", "keyEncipherment"],
    #         extended_key_usage=["serverAuth"],
    #         basic_constraints="critical,CA:FALSE",
    #     )
    #     return self._generate_certificate_from_profile(domain_dir, profile)
    def _generate_rsa_certificate(self, domain_dir: Path, cn: str) -> bool:
        profile = CertificateProfile(
            key_type="rsa",
            rsa_bits=2048,
            digest="sha256",
            cn=cn,
            subject=self._build_fixed_subject(cn),
            san_dns=[] if self._is_ip_address(cn) else [cn],
            san_ip=[cn] if self._is_ip_address(cn) else [],
            key_usage=["digitalSignature", "keyEncipherment"],
            extended_key_usage=["serverAuth"],
            basic_constraints="critical,CA:FALSE",
        )
        return self._generate_certificate_from_profile(domain_dir, profile)

    # def _generate_ecc_certificate(self, domain_dir: Path, cn: str) -> bool:
    #     """
    #     兼容旧接口：固定生成 EC-P256 / SHA256
    #     """
    #     profile = CertificateProfile(
    #         key_type="ec",
    #         ec_curve="P-256",
    #         digest="sha256",
    #         cn=cn,
    #         subject=f"/CN={cn}",
    #         san_dns=[] if self._is_ip_address(cn) else [cn],
    #         san_ip=[cn] if self._is_ip_address(cn) else [],
    #         key_usage=["digitalSignature"],
    #         extended_key_usage=["serverAuth"],
    #         basic_constraints="critical,CA:FALSE",
    #     )
    #     return self._generate_certificate_from_profile(domain_dir, profile)

    def _generate_ecc_certificate(self, domain_dir: Path, cn: str) -> bool:
        profile = CertificateProfile(
            key_type="ec",
            ec_curve="P-256",
            digest="sha256",
            cn=cn,
            subject=self._build_fixed_subject(cn),
            san_dns=[] if self._is_ip_address(cn) else [cn],
            san_ip=[cn] if self._is_ip_address(cn) else [],
            key_usage=["digitalSignature"],
            extended_key_usage=["serverAuth"],
            basic_constraints="critical,CA:FALSE",
        )
        return self._generate_certificate_from_profile(domain_dir, profile)


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