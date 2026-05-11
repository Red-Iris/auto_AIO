@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

title AutoAIO Security Test - Build GUI

echo ============================================================
echo   自动化安全测试平台 - GUI 打包工具
echo ============================================================
echo.

:: ============================================================
:: Step 1 - 检查 Python
:: ============================================================
echo [1/4] 检查 Python 环境...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到 Python，请先安装 Python 3.8+
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do echo        已检测到 Python %%v

:: ============================================================
:: Step 2 - 创建/激活虚拟环境
:: ============================================================
echo.
echo [2/4] 准备虚拟环境...

set VENV_DIR=.venv
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo        正在创建虚拟环境...
    python -m venv "%VENV_DIR%"
    if %errorlevel% neq 0 (
        echo [错误] 创建虚拟环境失败
        pause
        exit /b 1
    )
    echo        虚拟环境创建完成
) else (
    echo        使用现有虚拟环境
)

set PYTHON=%VENV_DIR%\Scripts\python.exe
set PIP=%VENV_DIR%\Scripts\pip.exe

:: ============================================================
:: Step 3 - 安装依赖（清华镜像优先，失败回退到官方源）
:: ============================================================
echo.
echo [3/4] 安装依赖包...

set PIP_MIRROR_PRIMARY=https://pypi.tuna.tsinghua.edu.cn/simple
set PIP_MIRROR_FALLBACK=https://pypi.org/simple

echo        升级 pip...
%PYTHON% -m pip install --upgrade pip --quiet

echo        安装项目依赖（镜像源: 清华大学）...
%PIP% install -r requirement.txt -i %PIP_MIRROR_PRIMARY% --quiet
if %errorlevel% neq 0 (
    echo [警告] 清华镜像安装失败，尝试官方 PyPI 源...
    %PIP% install -r requirement.txt -i %PIP_MIRROR_FALLBACK% --quiet
    if %errorlevel% neq 0 (
        echo [警告] 部分依赖安装失败，尝试继续...
    )
)

echo        验证关键依赖...
%PYTHON% -c "import PyQt5; import pyshark; print('        依赖检查通过')" >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 关键依赖缺失（PyQt5 / pyshark），请检查网络连接后重试
    pause
    exit /b 1
)

:: ============================================================
:: Step 4 - PyInstaller 打包
:: ============================================================
echo.
echo [4/4] 开始打包 GUI 可执行文件...

:: 清理旧的构建文件
if exist "build" rmdir /s /q "build"
if exist "dist\AutoAIO_Security_Test" rmdir /s /q "dist\AutoAIO_Security_Test"

echo        正在打包，请稍候（首次打包可能需 2-5 分钟）...
%PYTHON% -m PyInstaller AutoAIO_Security_Test.spec --noconfirm
if %errorlevel% neq 0 (
    echo.
    echo [错误] 打包失败！请检查上方错误信息。
    pause
    exit /b 1
)

:: ============================================================
:: 完成
:: ============================================================
echo.
echo ============================================================
echo   打包完成！
echo   输出路径: dist\AutoAIO_Security_Test.exe
echo ============================================================
echo.
echo 分发给同事时需要一并提供:
echo   1. dist\AutoAIO_Security_Test.exe  （主程序）
echo   2. setup.ps1                       （环境安装脚本）
echo   3. 告知对方先运行 setup.ps1 检测环境，再双击 exe
echo.

:: 打开输出目录
explorer dist

pause
endlocal
