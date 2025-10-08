#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S-DES 暴力破解演示脚本
展示多线程暴力破解的性能和时间统计
"""

import time
import threading
import sys
from sdes_core import SDES, BruteForceCracker

# 设置输出编码
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())


def demonstrate_brute_force():
    """演示暴力破解功能"""
    print("=== S-DES 暴力破解演示 ===\n")
    
    sdes = SDES()
    cracker = BruteForceCracker()
    
    # 设置测试用例
    plaintext = [1, 0, 1, 0, 0, 1, 0, 1]  # 8位明文
    key = [1, 0, 1, 0, 0, 1, 0, 1, 0, 1]  # 10位密钥
    
    print(f"明文: {''.join(map(str, plaintext))}")
    print(f"真实密钥: {''.join(map(str, key))}")
    
    # 加密得到密文
    ciphertext = sdes.encrypt(plaintext, key)
    print(f"密文: {''.join(map(str, ciphertext))}")
    print()
    
    # 测试不同线程数的性能
    thread_counts = [1, 2, 4, 8]
    
    for thread_count in thread_counts:
        print(f"--- 使用 {thread_count} 个线程 ---")
        
        start_time = time.time()
        found_key, elapsed_time = cracker.crack_key(plaintext, ciphertext, thread_count)
        end_time = time.time()
        
        if found_key != -1:
            found_key_bits = cracker._int_to_bits(found_key, 10)
            found_key_str = ''.join(map(str, found_key_bits))
            
            print(f"找到密钥: {found_key_str} (十进制: {found_key})")
            print(f"破解时间: {elapsed_time:.4f} 秒")
            print(f"验证: {'正确' if found_key_bits == key else '错误'}")
        else:
            print("未找到密钥")
        
        print()


def demonstrate_key_collision():
    """演示密钥冲突分析"""
    print("=== 密钥冲突分析演示 ===\n")
    
    cracker = BruteForceCracker()
    
    # 分析密钥冲突
    plaintext = [1, 0, 1, 0, 0, 1, 0, 1]
    ciphertext_map = cracker.analyze_key_collisions(plaintext)
    
    print(f"明文: {''.join(map(str, plaintext))}")
    print(f"总密文数: {len(ciphertext_map)}")
    
    # 统计冲突
    collision_count = 0
    max_collision = 0
    
    for ciphertext_tuple, keys in ciphertext_map.items():
        if len(keys) > 1:
            collision_count += 1
            max_collision = max(max_collision, len(keys))
    
    print(f"有冲突的密文数: {collision_count}")
    print(f"最大冲突数: {max_collision}")
    
    # 显示前5个冲突
    print("\n前5个密钥冲突示例:")
    count = 0
    for ciphertext_tuple, keys in ciphertext_map.items():
        if len(keys) > 1 and count < 5:
            ciphertext_str = ''.join(map(str, ciphertext_tuple))
            keys_str = ', '.join(map(str, keys))
            print(f"密文 {ciphertext_str} 对应密钥: {keys_str}")
            count += 1


def demonstrate_ascii_encryption():
    """演示ASCII加密功能"""
    print("=== ASCII加密演示 ===\n")
    
    sdes = SDES()
    key = [1, 0, 1, 0, 0, 1, 0, 1, 0, 1]
    
    test_strings = ["Hello", "World", "123", "ABC", "!@#"]
    
    print(f"密钥: {''.join(map(str, key))}")
    print()
    
    for text in test_strings:
        encrypted = sdes.encrypt_ascii(text, key)
        decrypted = sdes.decrypt_ascii(encrypted, key)
        
        print(f"原文: {text}")
        print(f"密文: {encrypted.encode('utf-8', errors='replace').decode('utf-8')}")
        print(f"解密: {decrypted}")
        print(f"正确: {'是' if text == decrypted else '否'}")
        print()


def main():
    """主函数"""
    print("S-DES 算法演示程序")
    print("=" * 50)
    
    # 演示暴力破解
    demonstrate_brute_force()
    
    # 演示密钥冲突分析
    demonstrate_key_collision()
    
    # 演示ASCII加密
    demonstrate_ascii_encryption()
    
    print("演示完成！")


if __name__ == "__main__":
    main()
