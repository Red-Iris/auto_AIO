#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AutoAIO 配置管理模块

支持便携模式（config.json 在程序目录）和用户目录模式。
优先级：程序目录 > 用户配置目录。写入始终写入程序目录。
"""

import json
import os
import sys
import shutil
from pathlib import Path
from typing import Any, Dict, Optional


def _normalize_path(path_str: str) -> str:
    """路径规范化：展开变量、转为绝对路径、统一扩展名小写"""
    if not path_str:
        return path_str
    # 展开 ~ 和环境变量
    expanded = os.path.expandvars(os.path.expanduser(path_str.strip().strip('"')))
    # 转为绝对路径
    abs_path = os.path.abspath(expanded)
    # 将文件扩展名统一为小写（仅影响后缀，不改变目录部分的大小写）
    root, ext = os.path.splitext(abs_path)
    return root + ext.lower()


def _app_dir() -> Path:
    """返回程序所在目录（打包后为 exe 所在目录，源码运行时为项目根目录）"""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def get_config_path() -> Path:
    """获取配置文件路径（程序目录下的 config.json）"""
    return _app_dir() / 'config.json'


def load_config() -> Dict[str, Any]:
    """
    加载配置。先读程序目录的便携配置，再合并用户目录配置。
    返回配置字典，文件不存在时返回空字典。
    """
    config = {}
    for loc in [get_config_path()]:
        try:
            if loc.is_file():
                with open(loc, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    config.update(data)
        except (json.JSONDecodeError, OSError):
            pass
    return config


def save_config(config: Dict[str, Any]) -> None:
    """保存配置到程序目录下的 config.json"""
    cfg_path = get_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def get_config_value(key: str, default: Any = None) -> Any:
    """读取单个配置项"""
    return load_config().get(key, default)


def set_config_value(key: str, value: Any) -> None:
    """写入单个配置项并持久化（路径类值自动规范化 .EXE 后缀）"""
    config = load_config()
    if isinstance(value, str) and key.endswith('_path'):
        value = _normalize_path(value)
    config[key] = value
    save_config(config)


# ————————————————————————
# 便捷方法：工具路径
# ————————————————————————

def get_tshark_path() -> Optional[str]:
    """从配置中读取用户设定的 TShark 路径"""
    val = get_config_value('tshark_path')
    if val and os.path.isfile(val):
        return val
    return None


def set_tshark_path(path: str) -> None:
    set_config_value('tshark_path', _normalize_path(path))


def get_cve_bin_tool_path() -> Optional[str]:
    """从配置中读取用户设定的 cve-bin-tool 路径"""
    val = get_config_value('cve_bin_tool_path')
    if val:
        return val
    return None


def set_cve_bin_tool_path(path: str) -> None:
    set_config_value('cve_bin_tool_path', _normalize_path(path))


def get_nvd_api_key() -> Optional[str]:
    return get_config_value('nvd_api_key')


def set_nvd_api_key(key: str) -> None:
    set_config_value('nvd_api_key', key)


def get_default_output_dir() -> Optional[str]:
    val = get_config_value('default_output_dir')
    if val and os.path.isdir(val):
        return val
    return None


def set_default_output_dir(path: str) -> None:
    set_config_value('default_output_dir', _normalize_path(path))


# ————————————————————————
# 外部工具可用性检测
# ————————————————————————

def check_tool(name: str, *commands) -> Optional[str]:
    """
    检测外部命令行工具是否可用。
    依次尝试给出的命令名（如 'tshark', 'tshark.exe'），返回第一个找到的路径，找不到返回 None。
    """
    for cmd in commands:
        found = shutil.which(cmd)
        if found:
            return found
    return None


def run_tool_check(tool_path: Optional[str]) -> bool:
    """
    通用工具验证：给定一个路径，检查它是否存在且可执行。
    支持 None（未配置）→ False。
    """
    if not tool_path:
        return False
    return os.path.isfile(tool_path)


def health_check() -> Dict[str, Any]:
    """
    全量环境检测。

    Returns:
        {
            'python': {'ok': bool, 'path': str|null, 'version': str|null},
            'tshark': {'ok': bool, 'path': str|null, 'version': str|null, 'configured_path': str|null},
            'nmap': {'ok': bool, 'path': str|null, 'version': str|null},
            'openssl': {'ok': bool, 'path': str|null, 'version': str|null},
            'cve_bin_tool': {'ok': bool, 'path': str|null, 'version': str|null, 'configured_path': str|null},
            'all_ok': bool
        }
    """
    import subprocess

    result = {'all_ok': True}

    # Python
    py_path = sys.executable
    py_version = sys.version.split()[0]
    py_ok = sys.version_info >= (3, 8)
    result['python'] = {
        'ok': py_ok,
        'path': py_path,
        'version': py_version
    }
    if not py_ok:
        result['all_ok'] = False

    # TShark
    from core import get_default_tshark_path
    configured_tshark = get_tshark_path()
    tshark_path = configured_tshark or get_default_tshark_path()
    tshark_ok = False
    tshark_version = None
    if tshark_path:
        tshark_ok, tshark_version = _try_version(tshark_path, ['--version'])
    result['tshark'] = {
        'ok': tshark_ok,
        'path': tshark_path,
        'version': tshark_version,
        'configured_path': configured_tshark
    }
    if not tshark_ok:
        result['all_ok'] = False

    # Nmap
    nmap_path = shutil.which('nmap')
    nmap_ok = False
    nmap_version = None
    if nmap_path:
        nmap_ok, nmap_version = _try_version(nmap_path, ['--version'])
    result['nmap'] = {
        'ok': nmap_ok,
        'path': nmap_path,
        'version': nmap_version
    }
    if not nmap_ok:
        result['all_ok'] = False

    # OpenSSL
    openssl_path = shutil.which('openssl')
    openssl_ok = False
    openssl_version = None
    if openssl_path:
        openssl_ok, openssl_version = _try_version(openssl_path, ['version'])
    result['openssl'] = {
        'ok': openssl_ok,
        'path': openssl_path,
        'version': openssl_version
    }
    if not openssl_ok:
        result['all_ok'] = False

    # cve-bin-tool
    configured_cve = get_cve_bin_tool_path()
    cve_path = None
    cve_ok = False
    cve_version = None
    try:
        from modules import VulnerabilityScannerModule
        cve_cmd = VulnerabilityScannerModule._find_cve_bin_tool(configured_cve)
        if cve_cmd:
            cve_path = ' '.join(cve_cmd)
            cve_ok, cve_version = _try_version(cve_cmd[0],
                                               ['--version'] if len(cve_cmd) == 1 else cve_cmd[1:],
                                               extra_args=cve_cmd[1:])
    except Exception:
        pass
    result['cve_bin_tool'] = {
        'ok': cve_ok,
        'path': cve_path,
        'version': cve_version,
        'configured_path': configured_cve
    }
    if not cve_ok:
        result['all_ok'] = False

    return result


def _try_version(exe: str, version_args: list, extra_args: Optional[list] = None) -> tuple:
    """尝试运行 tool --version，返回 (ok, version_string)"""
    import subprocess
    try:
        cmd = [exe]
        if extra_args:
            cmd += extra_args
        else:
            cmd += version_args
        startupinfo = None
        if sys.platform == 'win32':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            startupinfo=startupinfo
        )
        out = (r.stdout + r.stderr).strip()
        first_line = out.split('\n')[0].strip() if out else 'ok'
        return True, first_line
    except Exception:
        return False, None
