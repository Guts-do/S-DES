#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S-DES (Simplified Data Encryption Standard) 算法实现
包含完整的加密、解密、密钥扩展等功能
"""

import time
from typing import List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


class SDES:
    """S-DES算法实现类"""
    
    def __init__(self):
        # 定义所有置换盒和S盒
        self.P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]  # 密钥扩展P10置换
        self.P8 = [6, 3, 7, 4, 8, 5, 10, 9]         # 密钥扩展P8置换
        self.IP = [2, 6, 3, 1, 4, 8, 5, 7]          # 初始置换
        self.IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]      # 逆初始置换
        self.EP = [4, 1, 2, 3, 2, 3, 4, 1]          # 扩展置换
        self.SP = [2, 4, 3, 1]                      # 置换盒
        
        # S盒定义
        self.S1 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 0, 2]
        ]
        
        self.S2 = [
            [0, 1, 2, 3],
            [2, 3, 1, 0],
            [3, 0, 1, 2],
            [2, 1, 0, 3]
        ]
    
    def _permute(self, data: List[int], permutation: List[int]) -> List[int]:
        """执行置换操作"""
        return [data[i - 1] for i in permutation]
    
    def _left_shift(self, data: List[int], shift_count: int) -> List[int]:
        """左循环移位"""
        return data[shift_count:] + data[:shift_count]
    
    def _generate_subkeys(self, key: List[int]) -> Tuple[List[int], List[int]]:
        """生成子密钥k1和k2"""
        # P10置换
        p10_result = self._permute(key, self.P10)
        
        # 分割为左右两部分
        left_half = p10_result[:5]
        right_half = p10_result[5:]
        
        # 生成k1：左移1位后P8置换
        left_shift1 = self._left_shift(left_half, 1)
        right_shift1 = self._left_shift(right_half, 1)
        combined1 = left_shift1 + right_shift1
        k1 = self._permute(combined1, self.P8)
        
        # 生成k2：左移2位后P8置换
        left_shift2 = self._left_shift(left_half, 2)
        right_shift2 = self._left_shift(right_half, 2)
        combined2 = left_shift2 + right_shift2
        k2 = self._permute(combined2, self.P8)
        
        return k1, k2
    
    def _s_box_substitution(self, data: List[int]) -> List[int]:
        """S盒替换"""
        # 分割为两个4位
        left_part = data[:4]
        right_part = data[4:]
        
        # 处理左半部分（S1）
        row1 = left_part[0] * 2 + left_part[3]
        col1 = left_part[1] * 2 + left_part[2]
        s1_output = self.S1[row1][col1]
        
        # 处理右半部分（S2）
        row2 = right_part[0] * 2 + right_part[3]
        col2 = right_part[1] * 2 + right_part[2]
        s2_output = self.S2[row2][col2]
        
        # 转换为2位二进制
        result = []
        for i in range(1, -1, -1):
            result.append((s1_output >> i) & 1)
        for i in range(1, -1, -1):
            result.append((s2_output >> i) & 1)
        
        return result
    
    def _feistel_function(self, data: List[int], subkey: List[int]) -> List[int]:
        """Feistel函数"""
        # 扩展置换
        expanded = self._permute(data, self.EP)
        
        # 与子密钥异或
        xor_result = [expanded[i] ^ subkey[i] for i in range(8)]
        
        # S盒替换
        s_box_result = self._s_box_substitution(xor_result)
        
        # 置换盒
        permuted = self._permute(s_box_result, self.SP)
        
        return permuted
    
    def encrypt(self, plaintext: List[int], key: List[int]) -> List[int]:
        """加密函数"""
        # 生成子密钥
        k1, k2 = self._generate_subkeys(key)
        
        # 初始置换
        ip_result = self._permute(plaintext, self.IP)
        
        # 分割为左右两部分
        left = ip_result[:4]
        right = ip_result[4:]
        
        # 第一轮Feistel
        f1_result = self._feistel_function(right, k1)
        new_left = [left[i] ^ f1_result[i] for i in range(4)]
        new_right = right
        
        # 交换
        temp = new_left
        new_left = new_right
        new_right = temp
        
        # 第二轮Feistel
        f2_result = self._feistel_function(new_right, k2)
        final_left = [new_left[i] ^ f2_result[i] for i in range(4)]
        final_right = new_right
        
        # 合并
        combined = final_left + final_right
        
        # 逆初始置换
        ciphertext = self._permute(combined, self.IP_INV)
        
        return ciphertext
    
    def decrypt(self, ciphertext: List[int], key: List[int]) -> List[int]:
        """解密函数"""
        # 生成子密钥
        k1, k2 = self._generate_subkeys(key)
        
        # 初始置换
        ip_result = self._permute(ciphertext, self.IP)
        
        # 分割为左右两部分
        left = ip_result[:4]
        right = ip_result[4:]
        
        # 第一轮Feistel（使用k2）
        f1_result = self._feistel_function(right, k2)
        new_left = [left[i] ^ f1_result[i] for i in range(4)]
        new_right = right
        
        # 交换
        temp = new_left
        new_left = new_right
        new_right = temp
        
        # 第二轮Feistel（使用k1）
        f2_result = self._feistel_function(new_right, k1)
        final_left = [new_left[i] ^ f2_result[i] for i in range(4)]
        final_right = new_right
        
        # 合并
        combined = final_left + final_right
        
        # 逆初始置换
        plaintext = self._permute(combined, self.IP_INV)
        
        return plaintext
    
    def encrypt_ascii(self, text: str, key: List[int]) -> str:
        """ASCII字符串加密"""
        result = ""
        for char in text:
            # 将字符转换为8位二进制
            char_bits = [(ord(char) >> i) & 1 for i in range(7, -1, -1)]
            # 加密
            encrypted_bits = self.encrypt(char_bits, key)
            # 转换回字符
            encrypted_char = chr(sum(encrypted_bits[i] << (7-i) for i in range(8)))
            result += encrypted_char
        return result
    
    def decrypt_ascii(self, text: str, key: List[int]) -> str:
        """ASCII字符串解密"""
        result = ""
        for char in text:
            # 将字符转换为8位二进制
            char_bits = [(ord(char) >> i) & 1 for i in range(7, -1, -1)]
            # 解密
            decrypted_bits = self.decrypt(char_bits, key)
            # 转换回字符
            decrypted_char = chr(sum(decrypted_bits[i] << (7-i) for i in range(8)))
            result += decrypted_char
        return result


class BruteForceCracker:
    """暴力破解类"""
    
    def __init__(self):
        self.sdes = SDES()
    
    def _int_to_bits(self, value: int, bit_count: int) -> List[int]:
        """将整数转换为指定位数的二进制列表"""
        return [(value >> i) & 1 for i in range(bit_count-1, -1, -1)]
    
    def _bits_to_int(self, bits: List[int]) -> int:
        """将二进制列表转换为整数"""
        return sum(bits[i] << (len(bits)-1-i) for i in range(len(bits)))
    
    def crack_key(self, plaintext: List[int], ciphertext: List[int], 
                  max_threads: int = 4) -> Tuple[int, float]:
        """暴力破解密钥"""
        start_time = time.time()
        
        def test_key(key_int: int) -> bool:
            key_bits = self._int_to_bits(key_int, 10)
            try:
                result = self.sdes.encrypt(plaintext, key_bits)
                return result == ciphertext
            except:
                return False
        
        # 使用多线程进行暴力破解
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # 提交所有可能的密钥（2^10 = 1024种）
            futures = []
            for key_int in range(1024):
                future = executor.submit(test_key, key_int)
                futures.append((key_int, future))
            
            # 检查结果
            for key_int, future in futures:
                if future.result():
                    end_time = time.time()
                    return key_int, end_time - start_time
        
        end_time = time.time()
        return -1, end_time - start_time  # 未找到密钥
    
    def find_all_keys(self, plaintext: List[int], ciphertext: List[int]) -> List[int]:
        """找到所有可能的密钥"""
        keys = []
        for key_int in range(1024):
            key_bits = self._int_to_bits(key_int, 10)
            try:
                result = self.sdes.encrypt(plaintext, key_bits)
                if result == ciphertext:
                    keys.append(key_int)
            except:
                continue
        return keys
    
    def analyze_key_collisions(self, plaintext: List[int]) -> dict:
        """分析密钥冲突"""
        ciphertext_map = {}
        
        for key_int in range(1024):
            key_bits = self._int_to_bits(key_int, 10)
            try:
                ciphertext = self.sdes.encrypt(plaintext, key_bits)
                ciphertext_tuple = tuple(ciphertext)
                
                if ciphertext_tuple not in ciphertext_map:
                    ciphertext_map[ciphertext_tuple] = []
                ciphertext_map[ciphertext_tuple].append(key_int)
            except:
                continue
        
        return ciphertext_map


def test_sdes():
    """测试S-DES算法"""
    sdes = SDES()
    
    # 测试用例
    plaintext = [1, 0, 1, 0, 0, 1, 0, 1]  # 8位明文
    key = [1, 0, 1, 0, 0, 1, 0, 1, 0, 1]  # 10位密钥
    
    print("明文:", plaintext)
    print("密钥:", key)
    
    # 加密
    ciphertext = sdes.encrypt(plaintext, key)
    print("密文:", ciphertext)
    
    # 解密
    decrypted = sdes.decrypt(ciphertext, key)
    print("解密:", decrypted)
    
    # 验证
    print("加密解密正确:", plaintext == decrypted)
    
    # ASCII测试
    ascii_text = "Hello"
    print(f"\nASCII原文: {ascii_text}")
    encrypted_ascii = sdes.encrypt_ascii(ascii_text, key)
    print(f"ASCII密文: {encrypted_ascii}")
    decrypted_ascii = sdes.decrypt_ascii(encrypted_ascii, key)
    print(f"ASCII解密: {decrypted_ascii}")


if __name__ == "__main__":
    test_sdes()
