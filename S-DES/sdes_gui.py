#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S-DES GUI界面实现
使用PyQt5创建用户友好的图形界面
"""

import sys
import time
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QGridLayout, QLabel, QLineEdit, 
                             QPushButton, QTextEdit, QTabWidget, QGroupBox,
                             QSpinBox, QProgressBar, QMessageBox, QFileDialog,
                             QCheckBox, QComboBox)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont, QIcon

from sdes_core import SDES, BruteForceCracker


class BruteForceThread(QThread):
    """暴力破解线程"""
    progress_updated = pyqtSignal(int)
    key_found = pyqtSignal(int, float)
    finished = pyqtSignal()
    
    def __init__(self, plaintext, ciphertext, max_threads=4):
        super().__init__()
        self.plaintext = plaintext
        self.ciphertext = ciphertext
        self.max_threads = max_threads
        self.cracker = BruteForceCracker()
    
    def run(self):
        """运行暴力破解"""
        start_time = time.time()
        
        def test_key(key_int):
            key_bits = self.cracker._int_to_bits(key_int, 10)
            try:
                result = self.cracker.sdes.encrypt(self.plaintext, key_bits)
                return result == self.ciphertext
            except:
                return False
        
        # 检查所有可能的密钥
        for key_int in range(1024):
            if test_key(key_int):
                end_time = time.time()
                self.key_found.emit(key_int, end_time - start_time)
                self.finished.emit()
                return
            
            # 更新进度
            progress = int((key_int + 1) / 1024 * 100)
            self.progress_updated.emit(progress)
        
        self.finished.emit()


class SDESMainWindow(QMainWindow):
    """S-DES主窗口"""
    
    def __init__(self):
        super().__init__()
        self.sdes = SDES()
        self.cracker = BruteForceCracker()
        self.brute_force_thread = None
        
        self.init_ui()
        self.setup_connections()
    
    def init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle("S-DES 加密解密系统")
        self.setGeometry(100, 100, 800, 600)
        
        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 创建主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 创建标签页
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # 添加各个标签页
        self.create_basic_tab()
        self.create_ascii_tab()
        self.create_brute_force_tab()
        self.create_analysis_tab()
        
        # 状态栏
        self.statusBar().showMessage("S-DES系统就绪")
    
    def create_basic_tab(self):
        """创建基本功能标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 输入组
        input_group = QGroupBox("输入")
        input_layout = QGridLayout(input_group)
        
        # 明文输入
        input_layout.addWidget(QLabel("明文 (8位二进制):"), 0, 0)
        self.plaintext_input = QLineEdit()
        self.plaintext_input.setPlaceholderText("例如: 10100101")
        input_layout.addWidget(self.plaintext_input, 0, 1)
        
        # 密钥输入
        input_layout.addWidget(QLabel("密钥 (10位二进制):"), 1, 0)
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("例如: 1010010101")
        input_layout.addWidget(self.key_input, 1, 1)
        
        # 按钮组
        button_layout = QHBoxLayout()
        
        self.encrypt_btn = QPushButton("加密")
        self.encrypt_btn.clicked.connect(self.encrypt_basic)
        button_layout.addWidget(self.encrypt_btn)
        
        self.decrypt_btn = QPushButton("解密")
        self.decrypt_btn.clicked.connect(self.decrypt_basic)
        button_layout.addWidget(self.decrypt_btn)
        
        self.clear_btn = QPushButton("清空")
        self.clear_btn.clicked.connect(self.clear_basic)
        button_layout.addWidget(self.clear_btn)
        
        # 输出组
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout(output_group)
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setMaximumHeight(150)
        output_layout.addWidget(self.result_text)
        
        # 添加到主布局
        layout.addWidget(input_group)
        layout.addLayout(button_layout)
        layout.addWidget(output_group)
        
        self.tab_widget.addTab(tab, "基本功能")
    
    def create_ascii_tab(self):
        """创建ASCII功能标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 输入组
        input_group = QGroupBox("ASCII输入")
        input_layout = QVBoxLayout(input_group)
        
        self.ascii_input = QTextEdit()
        self.ascii_input.setPlaceholderText("输入要加密的文本...")
        self.ascii_input.setMaximumHeight(100)
        input_layout.addWidget(self.ascii_input)
        
        # 密钥输入
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("密钥 (10位二进制):"))
        self.ascii_key_input = QLineEdit()
        self.ascii_key_input.setPlaceholderText("例如: 1010010101")
        key_layout.addWidget(self.ascii_key_input)
        input_layout.addLayout(key_layout)
        
        # 按钮组
        button_layout = QHBoxLayout()
        
        self.ascii_encrypt_btn = QPushButton("加密")
        self.ascii_encrypt_btn.clicked.connect(self.encrypt_ascii)
        button_layout.addWidget(self.ascii_encrypt_btn)
        
        self.ascii_decrypt_btn = QPushButton("解密")
        self.ascii_decrypt_btn.clicked.connect(self.decrypt_ascii)
        button_layout.addWidget(self.ascii_decrypt_btn)
        
        self.ascii_clear_btn = QPushButton("清空")
        self.ascii_clear_btn.clicked.connect(self.clear_ascii)
        button_layout.addWidget(self.ascii_clear_btn)
        
        # 输出组
        output_group = QGroupBox("ASCII输出")
        output_layout = QVBoxLayout(output_group)
        
        self.ascii_result_text = QTextEdit()
        self.ascii_result_text.setReadOnly(True)
        output_layout.addWidget(self.ascii_result_text)
        
        # 添加到主布局
        layout.addWidget(input_group)
        layout.addLayout(button_layout)
        layout.addWidget(output_group)
        
        self.tab_widget.addTab(tab, "ASCII功能")
    
    def create_brute_force_tab(self):
        """创建暴力破解标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 输入组
        input_group = QGroupBox("已知明密文对")
        input_layout = QGridLayout(input_group)
        
        input_layout.addWidget(QLabel("明文 (8位二进制):"), 0, 0)
        self.bf_plaintext_input = QLineEdit()
        self.bf_plaintext_input.setPlaceholderText("例如: 10100101")
        input_layout.addWidget(self.bf_plaintext_input, 0, 1)
        
        input_layout.addWidget(QLabel("密文 (8位二进制):"), 1, 0)
        self.bf_ciphertext_input = QLineEdit()
        self.bf_ciphertext_input.setPlaceholderText("例如: 11010110")
        input_layout.addWidget(self.bf_ciphertext_input, 1, 1)
        
        # 线程数设置
        thread_layout = QHBoxLayout()
        thread_layout.addWidget(QLabel("线程数:"))
        self.thread_spinbox = QSpinBox()
        self.thread_spinbox.setRange(1, 8)
        self.thread_spinbox.setValue(4)
        thread_layout.addWidget(self.thread_spinbox)
        thread_layout.addStretch()
        
        # 按钮
        self.bf_start_btn = QPushButton("开始暴力破解")
        self.bf_start_btn.clicked.connect(self.start_brute_force)
        thread_layout.addWidget(self.bf_start_btn)
        
        self.bf_stop_btn = QPushButton("停止")
        self.bf_stop_btn.clicked.connect(self.stop_brute_force)
        self.bf_stop_btn.setEnabled(False)
        thread_layout.addWidget(self.bf_stop_btn)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        # 结果显示
        result_group = QGroupBox("破解结果")
        result_layout = QVBoxLayout(result_group)
        
        self.bf_result_text = QTextEdit()
        self.bf_result_text.setReadOnly(True)
        result_layout.addWidget(self.bf_result_text)
        
        # 添加到主布局
        layout.addWidget(input_group)
        layout.addLayout(thread_layout)
        layout.addWidget(self.progress_bar)
        layout.addWidget(result_group)
        
        self.tab_widget.addTab(tab, "暴力破解")
    
    def create_analysis_tab(self):
        """创建分析标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 分析选项
        options_group = QGroupBox("分析选项")
        options_layout = QVBoxLayout(options_group)
        
        self.key_collision_check = QCheckBox("分析密钥冲突")
        self.ciphertext_collision_check = QCheckBox("分析密文冲突")
        options_layout.addWidget(self.key_collision_check)
        options_layout.addWidget(self.ciphertext_collision_check)
        
        # 分析按钮
        self.analyze_btn = QPushButton("开始分析")
        self.analyze_btn.clicked.connect(self.start_analysis)
        
        # 结果显示
        analysis_result_group = QGroupBox("分析结果")
        analysis_result_layout = QVBoxLayout(analysis_result_group)
        
        self.analysis_result_text = QTextEdit()
        self.analysis_result_text.setReadOnly(True)
        analysis_result_layout.addWidget(self.analysis_result_text)
        
        # 添加到主布局
        layout.addWidget(options_group)
        layout.addWidget(self.analyze_btn)
        layout.addWidget(analysis_result_group)
        
        self.tab_widget.addTab(tab, "算法分析")
    
    def setup_connections(self):
        """设置信号连接"""
        pass
    
    def parse_binary_input(self, text: str, expected_length: int) -> list:
        """解析二进制输入"""
        # 移除空格
        text = text.replace(" ", "")
        
        # 检查长度
        if len(text) != expected_length:
            raise ValueError(f"输入长度应为{expected_length}位")
        
        # 检查是否为二进制
        for char in text:
            if char not in "01":
                raise ValueError("输入应只包含0和1")
        
        return [int(char) for char in text]
    
    def encrypt_basic(self):
        """基本加密功能"""
        try:
            plaintext = self.parse_binary_input(self.plaintext_input.text(), 8)
            key = self.parse_binary_input(self.key_input.text(), 10)
            
            ciphertext = self.sdes.encrypt(plaintext, key)
            ciphertext_str = "".join(map(str, ciphertext))
            
            self.result_text.append(f"明文: {self.plaintext_input.text()}")
            self.result_text.append(f"密钥: {self.key_input.text()}")
            self.result_text.append(f"密文: {ciphertext_str}")
            self.result_text.append("-" * 40)
            
            self.statusBar().showMessage("加密完成")
            
        except ValueError as e:
            QMessageBox.warning(self, "输入错误", str(e))
        except Exception as e:
            QMessageBox.critical(self, "加密错误", str(e))
    
    def decrypt_basic(self):
        """基本解密功能"""
        try:
            ciphertext = self.parse_binary_input(self.plaintext_input.text(), 8)
            key = self.parse_binary_input(self.key_input.text(), 10)
            
            plaintext = self.sdes.decrypt(ciphertext, key)
            plaintext_str = "".join(map(str, plaintext))
            
            self.result_text.append(f"密文: {self.plaintext_input.text()}")
            self.result_text.append(f"密钥: {self.key_input.text()}")
            self.result_text.append(f"明文: {plaintext_str}")
            self.result_text.append("-" * 40)
            
            self.statusBar().showMessage("解密完成")
            
        except ValueError as e:
            QMessageBox.warning(self, "输入错误", str(e))
        except Exception as e:
            QMessageBox.critical(self, "解密错误", str(e))
    
    def clear_basic(self):
        """清空基本功能"""
        self.plaintext_input.clear()
        self.key_input.clear()
        self.result_text.clear()
    
    def encrypt_ascii(self):
        """ASCII加密"""
        try:
            text = self.ascii_input.toPlainText()
            if not text:
                QMessageBox.warning(self, "输入错误", "请输入要加密的文本")
                return
            
            key = self.parse_binary_input(self.ascii_key_input.text(), 10)
            
            encrypted_text = self.sdes.encrypt_ascii(text, key)
            
            self.ascii_result_text.append(f"原文: {text}")
            self.ascii_result_text.append(f"密钥: {self.ascii_key_input.text()}")
            self.ascii_result_text.append(f"密文: {encrypted_text}")
            self.ascii_result_text.append("-" * 40)
            
            self.statusBar().showMessage("ASCII加密完成")
            
        except ValueError as e:
            QMessageBox.warning(self, "输入错误", str(e))
        except Exception as e:
            QMessageBox.critical(self, "加密错误", str(e))
    
    def decrypt_ascii(self):
        """ASCII解密"""
        try:
            text = self.ascii_input.toPlainText()
            if not text:
                QMessageBox.warning(self, "输入错误", "请输入要解密的文本")
                return
            
            key = self.parse_binary_input(self.ascii_key_input.text(), 10)
            
            decrypted_text = self.sdes.decrypt_ascii(text, key)
            
            self.ascii_result_text.append(f"密文: {text}")
            self.ascii_result_text.append(f"密钥: {self.ascii_key_input.text()}")
            self.ascii_result_text.append(f"明文: {decrypted_text}")
            self.ascii_result_text.append("-" * 40)
            
            self.statusBar().showMessage("ASCII解密完成")
            
        except ValueError as e:
            QMessageBox.warning(self, "输入错误", str(e))
        except Exception as e:
            QMessageBox.critical(self, "解密错误", str(e))
    
    def clear_ascii(self):
        """清空ASCII功能"""
        self.ascii_input.clear()
        self.ascii_key_input.clear()
        self.ascii_result_text.clear()
    
    def start_brute_force(self):
        """开始暴力破解"""
        try:
            plaintext = self.parse_binary_input(self.bf_plaintext_input.text(), 8)
            ciphertext = self.parse_binary_input(self.bf_ciphertext_input.text(), 8)
            
            self.bf_result_text.clear()
            self.bf_result_text.append("开始暴力破解...")
            self.bf_result_text.append(f"明文: {self.bf_plaintext_input.text()}")
            self.bf_result_text.append(f"密文: {self.bf_ciphertext_input.text()}")
            self.bf_result_text.append("-" * 40)
            
            # 创建并启动线程
            self.brute_force_thread = BruteForceThread(
                plaintext, ciphertext, self.thread_spinbox.value()
            )
            self.brute_force_thread.progress_updated.connect(self.update_progress)
            self.brute_force_thread.key_found.connect(self.on_key_found)
            self.brute_force_thread.finished.connect(self.on_brute_force_finished)
            
            self.brute_force_thread.start()
            
            # 更新UI状态
            self.bf_start_btn.setEnabled(False)
            self.bf_stop_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            self.statusBar().showMessage("暴力破解进行中...")
            
        except ValueError as e:
            QMessageBox.warning(self, "输入错误", str(e))
        except Exception as e:
            QMessageBox.critical(self, "暴力破解错误", str(e))
    
    def stop_brute_force(self):
        """停止暴力破解"""
        if self.brute_force_thread and self.brute_force_thread.isRunning():
            self.brute_force_thread.terminate()
            self.brute_force_thread.wait()
            self.on_brute_force_finished()
    
    def update_progress(self, value):
        """更新进度条"""
        self.progress_bar.setValue(value)
    
    def on_key_found(self, key_int, elapsed_time):
        """找到密钥时的处理"""
        key_bits = self.cracker._int_to_bits(key_int, 10)
        key_str = "".join(map(str, key_bits))
        
        self.bf_result_text.append(f"找到密钥: {key_str} (十进制: {key_int})")
        self.bf_result_text.append(f"破解时间: {elapsed_time:.4f} 秒")
        self.bf_result_text.append("暴力破解完成!")
        
        self.statusBar().showMessage(f"找到密钥: {key_str}")
    
    def on_brute_force_finished(self):
        """暴力破解完成"""
        self.bf_start_btn.setEnabled(True)
        self.bf_stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        if not self.brute_force_thread or not self.brute_force_thread.isRunning():
            self.statusBar().showMessage("暴力破解完成")
    
    def start_analysis(self):
        """开始算法分析"""
        self.analysis_result_text.clear()
        
        if self.key_collision_check.isChecked():
            self.analyze_key_collisions()
        
        if self.ciphertext_collision_check.isChecked():
            self.analyze_ciphertext_collisions()
    
    def analyze_key_collisions(self):
        """分析密钥冲突"""
        self.analysis_result_text.append("=== 密钥冲突分析 ===")
        
        # 随机选择一个明文进行分析
        test_plaintext = [1, 0, 1, 0, 0, 1, 0, 1]
        ciphertext_map = self.cracker.analyze_key_collisions(test_plaintext)
        
        collision_count = 0
        for ciphertext_tuple, keys in ciphertext_map.items():
            if len(keys) > 1:
                collision_count += 1
                ciphertext_str = "".join(map(str, ciphertext_tuple))
                keys_str = ", ".join(map(str, keys))
                self.analysis_result_text.append(
                    f"密文 {ciphertext_str} 对应密钥: {keys_str}"
                )
        
        self.analysis_result_text.append(f"发现 {collision_count} 个密文冲突")
        self.analysis_result_text.append("-" * 40)
    
    def analyze_ciphertext_collisions(self):
        """分析密文冲突"""
        self.analysis_result_text.append("=== 密文冲突分析 ===")
        
        # 分析不同明文产生相同密文的情况
        plaintexts = [
            [1, 0, 1, 0, 0, 1, 0, 1],
            [0, 1, 0, 1, 1, 0, 1, 0],
            [1, 1, 0, 0, 1, 1, 0, 0]
        ]
        
        ciphertext_map = {}
        for plaintext in plaintexts:
            for key_int in range(1024):
                key_bits = self.cracker._int_to_bits(key_int, 10)
                try:
                    ciphertext = self.sdes.encrypt(plaintext, key_bits)
                    ciphertext_tuple = tuple(ciphertext)
                    
                    if ciphertext_tuple not in ciphertext_map:
                        ciphertext_map[ciphertext_tuple] = []
                    ciphertext_map[ciphertext_tuple].append((plaintext, key_int))
                except:
                    continue
        
        collision_count = 0
        for ciphertext_tuple, pairs in ciphertext_map.items():
            if len(pairs) > 1:
                collision_count += 1
                ciphertext_str = "".join(map(str, ciphertext_tuple))
                self.analysis_result_text.append(f"密文 {ciphertext_str} 对应:")
                for plaintext, key in pairs:
                    plaintext_str = "".join(map(str, plaintext))
                    self.analysis_result_text.append(f"  明文: {plaintext_str}, 密钥: {key}")
        
        self.analysis_result_text.append(f"发现 {collision_count} 个密文冲突")
        self.analysis_result_text.append("-" * 40)


def main():
    """主函数"""
    app = QApplication(sys.argv)
    
    # 设置应用程序信息
    app.setApplicationName("S-DES 加密解密系统")
    app.setApplicationVersion("1.0")
    
    # 创建主窗口
    window = SDESMainWindow()
    window.show()
    
    # 运行应用程序
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
