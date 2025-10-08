# S-DES 开发手册

## 项目概述
S-DES (Simplified Data Encryption Standard) 教学用加密算法实现，包含加密解密、暴力破解、算法分析等功能。

**技术栈**: Python 3.6+ + PyQt5 + ThreadPoolExecutor

## 核心组件

### 1. SDES类 - 核心算法
```python
class SDES:
    def encrypt(self, plaintext: List[int], key: List[int]) -> List[int]:
        """加密8位二进制数据"""
    
    def decrypt(self, ciphertext: List[int], key: List[int]) -> List[int]:
        """解密8位二进制数据"""
    
    def encrypt_ascii(self, text: str, key: List[int]) -> str:
        """ASCII字符串加密"""
    
    def decrypt_ascii(self, text: str, key: List[int]) -> str:
        """ASCII字符串解密"""
```

### 2. BruteForceCracker类 - 暴力破解
```python
class BruteForceCracker:
    def crack_key(self, plaintext: List[int], ciphertext: List[int], 
                  max_threads: int = 4) -> Tuple[int, float]:
        """多线程暴力破解，返回(密钥, 耗时)"""
    
    def analyze_key_collisions(self, plaintext: List[int]) -> dict:
        """分析密钥冲突，返回{密文: [密钥列表]}"""
```

### 3. GUI组件 - 用户界面
```python
class SDESMainWindow(QMainWindow):
    """主窗口，包含4个功能标签页"""
    
class BruteForceThread(QThread):
    """多线程暴力破解，支持进度更新"""
```

## 关键算法实现

### 密钥扩展
```python
def _generate_subkeys(self, key: List[int]) -> Tuple[List[int], List[int]]:
    # P10置换 -> 分割 -> 左移 -> P8置换
    p10_result = self._permute(key, self.P10)
    left_half, right_half = p10_result[:5], p10_result[5:]
    
    # 生成k1: 左移1位
    k1 = self._permute(self._left_shift(left_half, 1) + 
                      self._left_shift(right_half, 1), self.P8)
    
    # 生成k2: 左移2位  
    k2 = self._permute(self._left_shift(left_half, 2) + 
                      self._left_shift(right_half, 2), self.P8)
    return k1, k2
```

### Feistel函数
```python
def _feistel_function(self, data: List[int], subkey: List[int]) -> List[int]:
    # 扩展置换 -> 异或 -> S盒 -> 置换盒
    expanded = self._permute(data, self.EP)
    xor_result = [expanded[i] ^ subkey[i] for i in range(8)]
    s_box_result = self._s_box_substitution(xor_result)
    return self._permute(s_box_result, self.SP)
```

### 多线程暴力破解
```python
def crack_key(self, plaintext: List[int], ciphertext: List[int], 
              max_threads: int = 4) -> Tuple[int, float]:
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(test_key, i) for i in range(1024)]
        for key_int, future in enumerate(futures):
            if future.result():
                return key_int, time.time() - start_time
    return -1, time.time() - start_time
```

## 使用示例

### 基本加密解密
```python
from sdes_core import SDES

sdes = SDES()
plaintext = [1, 0, 1, 0, 0, 1, 0, 1]
key = [1, 0, 1, 0, 0, 1, 0, 1, 0, 1]

# 加密
ciphertext = sdes.encrypt(plaintext, key)

# 解密
decrypted = sdes.decrypt(ciphertext, key)
```

### 暴力破解
```python
from sdes_core import BruteForceCracker

cracker = BruteForceCracker()
found_key, elapsed_time = cracker.crack_key(plaintext, ciphertext)
print(f"Found key: {found_key}, Time: {elapsed_time:.4f}s")
```

### GUI启动
```python
from sdes_gui import SDESMainWindow
from PyQt5.QtWidgets import QApplication
import sys

app = QApplication(sys.argv)
window = SDESMainWindow()
window.show()
sys.exit(app.exec_())
```

## 文件结构
```
S-DES/
├── sdes_core.py      # 核心算法实现
├── sdes_gui.py       # GUI界面
├── test_sdes.py      # 测试套件
├── demo_sdes.py      # 演示脚本
├── run_sdes.py       # 启动脚本
└── *.md              # 文档文件
```

## 运行方式
```bash
# GUI界面
python sdes_gui.py

# 运行测试
python test_sdes.py

# 运行演示
python demo_sdes.py
```

## 扩展开发

### 添加新算法
```python
class NewCipher(SDES):
    def __init__(self):
        super().__init__()
        # 定义新的置换盒
        self.NEW_PBOX = [1, 2, 3, 4, 5, 6, 7, 8]
```

### 添加新测试
```python
class TestNewFeature(unittest.TestCase):
    def test_new_feature(self):
        # 测试新功能
        pass
```

## 注意事项
1. 输入必须是8位明文和10位密钥
2. 所有接口包含参数验证
3. GUI使用多线程避免界面卡顿
4. 遵循PEP 8编码规范