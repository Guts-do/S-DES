#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S-DES 系统启动脚本
"""

import sys
import os

def check_dependencies():
    """检查依赖"""
    try:
        import PyQt5
        print("PyQt5 已安装")
    except ImportError:
        print("错误: 未安装 PyQt5")
        print("请运行: pip install -r requirements.txt")
        return False
    return True

def main():
    """主函数"""
    print("=== S-DES 加密解密系统 ===")
    
    # 检查依赖
    if not check_dependencies():
        sys.exit(1)
    
    # 导入并运行GUI
    try:
        from sdes_gui import main as gui_main
        gui_main()
    except ImportError as e:
        print(f"导入错误: {e}")
        print("请确保所有文件都在同一目录下")
        sys.exit(1)
    except Exception as e:
        print(f"运行错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
