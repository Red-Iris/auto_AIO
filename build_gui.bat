@echo off
echo 正在打包AutoAIO安全测试平台GUI版本...
echo.

REM 检查是否安装了PyInstaller
pip list | findstr "PyInstaller" >nul
if %errorlevel% neq 0 (
    echo 正在安装PyInstaller...
    pip install pyinstaller
)

REM 检查是否安装了PyQt5
pip list | findstr "PyQt5" >nul
if %errorlevel% neq 0 (
    echo 正在安装PyQt5...
    pip install PyQt5
)

REM 打包应用
echo 开始打包过程...
pyinstaller build_gui.spec

if %errorlevel% equ 0 (
    echo.
    echo 打包成功！
    echo 可执行文件位于: dist\AutoAIO_Security_Test.exe
    echo.
    echo 将整个dist目录分发给同事即可，他们双击exe文件就能直接使用！
) else (
    echo.
    echo 打包失败，请检查错误信息
)

pause