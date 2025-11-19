import hashlib
from Crypto.Cipher import AES, DES 
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
import os
import binascii

# --- 1. 弱雜湊 (B303, B324) ---
def check_hashes():
    # B303: 弱點 SHA1
    data_sha1 = hashlib.sha1(b"sha1 data")
    
    # B324: 弱點 MD5
    data_md5 = hashlib.md5(b"md5 data")
    
    print("Hashes checked.")

# --- 2. 量子脆弱的非對稱加密 (PQC 核心目標) ---
def check_asymmetric():
    # B413_RSA_WEAK_SIZE: 密鑰長度不足 (CRITICAL)
    # 應標記為 < 2048
    key_weak = RSA.generate(1024) 
    
    # B413_RSA: 密鑰長度足夠 (PQC 遷移目標)
    # 應標記為 >= 2048
    key_strong = RSA.generate(3072)
    
    print("Asymmetric keys generated.")

# --- 3. 弱加密與不安全的使用樣式 (AES/DES) ---
def check_symmetric():
    key_des = b'8bytes!.' # DES 密钥
    key_aes = os.urandom(16) # AES 密钥
    
    # B304: 弱加密 DES
    cipher_des = DES.new(key_des, AES.MODE_ECB)
    
    # B413_AES_WEAK: AES/ECB 模式 (不安全模式)
    cipher_aes_ecb = AES.new(key_aes, AES.MODE_ECB) 
    
    # B413_IV_WEAK: CBC 模式 IV 缺失 (樣式漏洞)
    # 這裡故意省略 iv= 參數
    cipher_aes_cbc_fail = AES.new(key_aes, AES.MODE_CBC) 
    
    # B413_AES_SAFE: AES/GCM 模式 (可接受的資產)
    # GCM 模式不需要 IV 參數 (它使用 nonce)，應被視為安全資產
    cipher_aes_safe = AES.new(key_aes, AES.MODE_GCM) 
    
    print("Symmetric tests complete.")

if __name__ == "__main__":
    check_hashes()
    check_asymmetric()
    check_symmetric()