@echo off
chcp 65001
echo S-DES 加密解密系统
echo ==================
echo.
echo 请选择要运行的程序:
echo 1. GUI界面程序
echo 2. 测试程序
echo 3. 演示程序
echo 4. 退出
echo.
set /p choice=请输入选择 (1-4): 

if "%choice%"=="1" (
    echo 启动GUI界面...
    python sdes_gui.py
) else if "%choice%"=="2" (
    echo 运行测试程序...
    python test_sdes.py
) else if "%choice%"=="3" (
    echo 运行演示程序...
    python demo_sdes.py
) else if "%choice%"=="4" (
    echo 退出程序
    exit
) else (
    echo 无效选择，请重新运行程序
)

pause
