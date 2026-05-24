import ast
import json
from datetime import datetime

# --- PQC 知識庫與修復建議 (PQC_KNOWLEDGE_BASE) ---
PQC_KNOWLEDGE_BASE = {
# 升級說明：已全面對標 IBM CBOM / CycloneDX 1.6 標準，加入 OID 與工業級 Crypto 屬性定義
    # 1. 傳統弱雜湊 (Classic Weak Hashes)
    "B303": {
        "type": "WEAK_HASH_SHA1", 
        "algorithm": "SHA-1", 
        "crypto_type": "hash", 
        "oid": "1.3.14.3.2.26",
        "message": "使用了 SHA1 雜湊算法。", 
        "fix": "替換為 hashlib.sha256/sha3，SHA1 對碰撞攻擊是脆弱的。"
    },
    "B324": {
        "type": "WEAK_HASH_MD5", 
        "algorithm": "MD5", 
        "crypto_type": "hash", 
        "oid": "1.2.840.113549.2.5",
        "message": "使用了 MD5 雜湊算法。", 
        "fix": "必須移除 MD5，替換為 SHA256。"
    },

    # 2. 傳統弱對稱加密算法 (Classic Weak Ciphers)
    "B304": {
        "type": "WEAK_CIPHER_DES", 
        "algorithm": "DES", 
        "crypto_type": "symmetric", 
        "oid": "1.2.840.113549.3.7", # DES-EDE3-CBC 範例
        "message": "使用了 DES/3DES 弱加密算法。", 
        "fix": "停用 DES/3DES，改用 AES-256 GCM 模式。"
    },

    # 3. 量子脆弱非對稱資產 (Quantum-Vulnerable Assets)
    "B413_RSA": {
        "type": "PQC_TARGET_RSA", 
        "algorithm": "RSA", 
        "crypto_type": "public-key", 
        "oid": "1.2.840.113549.1.1.1",
        "message": "發現 RSA 密鑰生成。", 
        "fix": "量子脆弱：考慮替換為 CRYSTALS-Kyber (ML-KEM) 或 Dilithium (ML-DSA)。"
    },
    "B413_RSA_WEAK_SIZE": {
        "type": "WEAK_ASSET_RSA", 
        "algorithm": "RSA", 
        "crypto_type": "public-key", 
        "oid": "1.2.840.113549.1.1.1",
        "message": "發現 RSA 密鑰長度小於 2048 bits，對暴力破解脆弱。", 
        "fix": "將密鑰長度至少增加到 2048/4096 bits，並規劃 PQC 遷移。"
    },
    "B413_ECC": { 
        "type": "PQC_TARGET_ECC", 
        "algorithm": "ECC", 
        "crypto_type": "public-key", 
        "oid": "1.2.840.10045.2.1",
        "message": "發現 ECC/ECDSA/ECDH 橢圓曲線加密資產。", 
        "fix": "核心量子脆弱資產，建議替換為 CRYSTALS-Dilithium/Falcon。"
    },

    # 4. 對稱加密與運作樣式風險 (Symmetric Modes & IV)
    "B413_AES_WEAK": {
        "type": "WEAK_CIPHER_MODE", 
        "algorithm": "AES-ECB", 
        "crypto_type": "symmetric", 
        "oid": "2.16.840.1.101.3.4.1.1", # AES-128-ECB
        "message": "使用了不安全的 AES/ECB 模式。", 
        "fix": "替換為 AES-256 GCM 或 CCM 模式，確保認證性。"
    },
    "B413_AES_SAFE": {
        "type": "TRADITIONAL_AES_ASSET", 
        "algorithm": "AES", 
        "crypto_type": "symmetric", 
        "oid": "2.16.840.1.101.3.4.1.46", # AES-256-GCM
        "message": "使用了 AES 加密資產。", 
        "fix": "這是一個抗量子資產。請確保 IV/Nonce 是正確生成的。"
    },
    "B413_IV_WEAK": {
        "type": "WEAK_IV_NONCE", 
        "algorithm": "AES-Mode-Without-IV", 
        "crypto_type": "symmetric", 
        "oid": "2.16.840.1.101.3.4.1.2", # AES-128-CBC 範例
        "message": "在 CBC/CFB 模式中，未偵測到 IV/Nonce 參數，易受重放攻擊。", 
        "fix": "必須使用 os.urandom (Python) 或 SecureRandom (Java) 創隨機 IV。"
    },

    # 5. 後量子密碼學正面識別 (PQC Ready - FIPS 標準)
    "B501_KYBER": {
        "type": "PQC_KEM_ML_KEM", 
        "algorithm": "ML-KEM", 
        "crypto_type": "kem", 
        "oid": "2.16.840.1.101.3.4.4.1", # NIST FIPS 203 標準 OID
        "message": "發現 NIST 標準 PQC 算法：ML-KEM (Kyber)。", 
        "fix": "PQC READY。請確保實作符合 FIPS 203 標準。"
    },
    "B502_DILITHIUM": {
        "type": "PQC_SIGN_ML_DSA", 
        "algorithm": "ML-DSA", 
        "crypto_type": "signature", 
        "oid": "2.16.840.1.101.3.4.3.17", # NIST FIPS 204 標準 OID
        "message": "發現 NIST 標準 PQC 算法：ML-DSA (Dilithium)。", 
        "fix": "PQC READY。請確保實作符合 FIPS 204 標準。"
    },

    # 6. 硬編碼與機密洩漏風險 (Hardcoded Secrets)
    "B105_HARDCODED_SECRET": {
        "type": "SECRET_LEAKAGE", 
        "algorithm": "Hardcoded-Secret", 
        "crypto_type": "secret", 
        "oid": "N/A",
        "message": "發現硬編碼密鑰，可能導致密鑰洩露，影響 PQC 遷移後的安全性。", 
        "fix": "將密鑰儲存於環境變數或專門的密鑰管理器中。"
    },
    "B702_HARDCODED_KEY": {
        "type": "HARDCODED_SECRET_KEY", 
        "algorithm": "Hardcoded-Crypto-Key", 
        "crypto_type": "secret", 
        "oid": "N/A",
        "message": "偵測到疑似硬編碼的加密金鑰。", 
        "fix": "絕對禁止在程式碼中寫死金鑰。請改用環境變數或 KMS。"
    },
    "B706_HARDCODED_PASSWORD": {
        "type": "HARDCODED_PASSWORD", 
        "algorithm": "Hardcoded-Password", 
        "crypto_type": "secret", 
        "oid": "N/A",
        "message": "偵測到疑似硬編碼的密碼。", 
        "fix": "請勿將密碼儲存在原始碼中。"
    },
    "B707_HARDCODED_AWS": {
        "type": "HARDCODED_CLOUD_CREDENTIAL", 
        "algorithm": "Cloud-Credential", 
        "crypto_type": "secret", 
        "oid": "N/A",
        "message": "偵測到硬編碼 AWS Key (AKIA...)。", 
        "fix": "使用 IAM Role，禁止寫死雲端憑證。"
    },
    "B708_HARDCODED_TOKEN": {
        "type": "HARDCODED_API_TOKEN", 
        "algorithm": "API-Token", 
        "crypto_type": "secret", 
        "oid": "N/A",
        "message": "偵測到疑似硬編碼 API Token。", 
        "fix": "動態生成 Token 並採用機密隔離存取。"
    },
    "B709_HARDCODED_PQC_SK": {
        "type": "HARDCODED_PQC_PRIVATE_KEY", 
        "algorithm": "PQC-Private-Key", 
        "crypto_type": "secret", 
        "oid": "N/A",
        "message": "偵測到疑似 PQC 私鑰硬編碼。", 
        "fix": "PQC 私鑰極為敏感，洩漏將導致後量子防禦失效，請立刻移除並重新生成。"
    },

    # 7. 進階參數與演算法實作檢查 (Advanced Rules)
    "B701_WEAK_RNG": {
        "type": "WEAK_RANDOM_SOURCE", 
        "algorithm": "Insecure-RNG", 
        "crypto_type": "rng", 
        "oid": "N/A",
        "message": "使用弱亂數來源 (如 random)。", 
        "fix": "改用具有密碼學安全強度的隨機數生成器（如 os.urandom 或 SecureRandom）。"
    },
    "B415_ECC_WEAK_CURVE": {
        "type": "WEAK_ECC_CURVE", 
        "algorithm": "ECC-Weak-Curve", 
        "crypto_type": "public-key", 
        "oid": "1.3.132.0.33", # SECP192R1 範例 OID
        "message": "弱橢圓曲線 (如 P-192, SECP192)。", 
        "fix": "停用弱曲線，轉換至 NIST P-256 (2.16.840.10045.3.1.7) 或更高標準。"
    },
    "B703_WEAK_KDF_ITERATIONS": {
        "type": "WEAK_KDF_ITERATION_COUNT", 
        "algorithm": "PBKDF2", 
        "crypto_type": "kdf", 
        "oid": "1.2.840.113549.1.5.12",
        "message": "PBKDF2 密鑰衍生迭代次數過低。", 
        "fix": "遵守 OWASP / NIST 規範，將疊代次數提升至 600,000 次以上。"
    },
    "B710_SHORT_SALT": {
        "type": "INSUFFICIENT_SALT_LENGTH", 
        "algorithm": "Salt-Generation", 
        "crypto_type": "salt", 
        "oid": "N/A",
        "message": "Salt 長度不足，無法有效防禦彩虹表攻擊。", 
        "fix": "Salt 長度應大於等於 16 bytes，確保遷移後系統的抗碰撞隨機性。"
    },
    "B416_GCM_NONCE_LENGTH": {
        "type": "RISKY_GCM_NONCE_LENGTH", 
        "algorithm": "AES-GCM", 
        "crypto_type": "symmetric", 
        "oid": "2.16.840.1.101.3.4.1.46",
        "message": "GCM Nonce 長度非 12 bytes，可能導致密鑰流洩漏風險。", 
        "fix": "根據 NIST SP 800-38D 標準，強制將 GCM Nonce 固定為 12 bytes (96 bits)。"
    }

}

LANGUAGE_SPECIFIC_RULES = {
    "cpp": {
        # --- 弱雜湊 MD5 (對應 B324) ---
        "MD5": "B324",
        "MD5_Init": "B324",
        "EVP_md5": "B324",

        # --- 弱雜湊 SHA1 (對應 B303) ---
        "SHA1": "B303",
        "SHA1_Init": "B303",
        "EVP_sha1": "B303",

        # --- 量子脆弱資產 RSA (對應 B413_RSA) ---
        # 你的 scanner_cpp.py 已經有寫邏輯，如果抓到 RSA_generate_key，
        # 會再進一步檢查 bits，若小於 2048 會自動升級成 B413_RSA_WEAK_SIZE
        "RSA_generate_key": "B413_RSA",
        "RSA_generate_key_ex": "B413_RSA",

        # --- 傳統 DES 弱加密直接呼叫 (對應 B304) ---
        # (註：EVP_EncryptInit_ex 裡的 DES 已經在你的 _check_advanced_crypto_rules 處理了)
        "DES_random_key": "B304",
        "DES_set_key": "B304",
        "DES_set_key_checked": "B304",
        "DES_ncbc_encrypt": "B304"
    }
}

# --- 2. 狀態判斷函數 (對應 website.py 的圖表邏輯) ---
def _determine_pqc_status(rule_id):
    """決定資產的 PQC 狀態 (用於圖表與 CBOM)"""
    if "HARDCODED" in rule_id: return "CRITICAL_SECRET_LEAK"
    if any(k in rule_id for k in ["SHA1", "MD5", "DES"]): return "VULNERABLE (CLASSIC)"
    if any(k in rule_id for k in ["RSA", "ECC", "WEAK"]): return "VULNERABLE (QUANTUM)"
    if any(k in rule_id for k in ["KYBER", "DILITHIUM"]): return "PQC_READY"
    if "AES" in rule_id and "SAFE" in rule_id: return "SAFE (QUANTUM-RESISTANT)"
    return "UNKNOWN"

# --- 3. CBOM 生成函數 (對應 website.py 的下載按鈕) ---
def generate_cbom_json(findings):
    import uuid
    from datetime import datetime
    
    # 1. 建立動態唯一識別碼 (URN UUID)
    bom_uuid = f"urn:uuid:{uuid.uuid4()}"
    
    cbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": bom_uuid,
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z", # 標準 UTC 時間戳
            "tool": {
                "components": [
                    {
                        "type": "application",
                        "name": "PQC Hybrid Auditor (Multi-Language)",
                        "version": "2.0",
                        "description": "AI-Driven Cryptographic Asset Inventory & Vulnerability Detection Framework"
                    }
                ]
            },
            "component": {
                "bom-ref": "target-project",
                "type": "application",
                "name": "Analyzed-Source-Code-Base",
                "version": "1.0.0"
            }
        },
        "components": [],
        "dependencies": [] # 🟢 相依性鏈區塊
    }
    
    # 用於紀錄所有組件的 Ref，建立相依性關係
    dependent_refs = []
    
    for idx, finding in enumerate(findings):
        rule_id = finding['RuleID']
        rule_info = PQC_KNOWLEDGE_BASE.get(rule_id, {})
        asset_ref = f"crypto-asset-{idx+1}"
        dependent_refs.append(asset_ref)
        
        # 2. 智慧判定量子防禦狀態 (Quantum Resistance Assessment)
        quantum_status = "vulnerable"
        crypto_strength = 0
        
        if "B501" in rule_id or "B502" in rule_id:
            quantum_status = "supported"   # PQC Ready
            crypto_strength = 128          # 後量子安全基準
        elif "AES" in rule_id and "SAFE" in rule_id:
            quantum_status = "resistant"   # 抗量子對稱加密
            crypto_strength = 256 if "256" in finding.get('CodeSnippet', '') else 128
            
        # 3. 動態解析密碼學進階屬性 (參數提取優化)
        snippet = finding.get('CodeSnippet', '')
        mode = "unknown"
        padding = "unknown"
        
        # 從代碼片段抽樣判定 Mode
        if "ECB" in snippet.upper(): mode = "ECB"
        elif "CBC" in snippet.upper(): mode = "CBC"
        elif "GCM" in snippet.upper(): mode = "GCM"
        elif "CFB" in snippet.upper(): mode = "CFB"
        
        if "PKCS5" in snippet.upper(): padding = "PKCS5Padding"
        elif "NOPADDING" in snippet.upper(): padding = "NoPadding"

        # 4. 構建符合 CycloneDX Crypto 延伸標準的物件
        crypto_component = {
            "type": "cryptographic-asset",
            "bom-ref": asset_ref,
            "name": rule_info.get("algorithm", "UNKNOWN"),
            "version": "N/A",
            "description": finding.get('Message', rule_info.get('message', 'N/A')),
            "cryptoProperties": {
                "assetType": rule_info.get("crypto_type", "unknown"),
                "algorithmProperties": {
                    "name": rule_info.get("algorithm", "UNKNOWN"),
                    "oid": rule_info.get("oid", "N/A"),
                    "cryptoStrength": crypto_strength,
                    "executionEnvironment": "software"
                },
                "oid": rule_info.get("oid", "N/A")
            },
            "evidence": {
                "source": {
                    "location": finding['Location'],
                    "codeSnippet": snippet
                }
            },
            # 5. 擴充符合 IBM 治理要求的自訂邊界屬性 (Metadata Extensions)
            "properties": [
                {"name": "pqc:rule-id", "value": rule_id},
                {"name": "pqc:algorithm-mode", "value": mode},
                {"name": "pqc:algorithm-padding", "value": padding},
                {"name": "pqc:migration-urgency", "value": "HIGH" if quantum_status == "vulnerable" else "LOW"},
                {"name": "pqc:quantum-resistance-status", "value": quantum_status},
                {"name": "pqc:remediation-strategy", "value": finding.get('FixSuggestion', rule_info.get('fix', 'N/A'))}
            ]
        }
        
        cbom_data["components"].append(crypto_component)
        
    # 6. 建立專案與加密資產的相依性鏈 (Dependencies Graph)
    if dependent_refs:
        cbom_data["dependencies"].append({
            "dependsOn": dependent_refs,
            "ref": "target-project"
        })
        
    return cbom_data

# --- 4. 掃描器基類 ---
class BaseScanner:
    def __init__(self, filename):
        self.filename = filename
        self.findings = []

    def get_rule_id(self, lang, func_name):
        """ 🚀 子類別專用：向 Base 查詢各語言函式對應的通用 RuleID """
        lang_rules = LANGUAGE_SPECIFIC_RULES.get(lang.lower(), {})
        return lang_rules.get(func_name)

    def report_finding(self, node_or_str, line, rule_id, custom_message=None):
        """ 統一生成報告格式 """
        info = PQC_KNOWLEDGE_BASE.get(rule_id, {"type": "UNKNOWN", "message": "未知規則", "fix": "N/A"})
        
        if isinstance(node_or_str, str):
            code_snippet = node_or_str
        elif isinstance(node_or_str, (ast.Call, ast.Attribute)):
            code_snippet = ast.unparse(node_or_str).strip()
        else:
            code_snippet = str(node_or_str)

        return {
            "RuleID": rule_id,
            "Type": info.get('type', 'UNKNOWN_TYPE'),
            "Location": f"{self.filename}:{line}",
            "CodeSnippet": code_snippet,
            "Message": custom_message if custom_message else info.get('message', 'N/A'),
            "FixSuggestion": info.get('fix', 'N/A')
        }
    
    def scan(self, filepath):
        raise NotImplementedError("子類別必須實作 scan 方法")
    
def _determine_pqc_status(rule_id):
    """決定資產的 PQC 狀態 (用於圖表與 CBOM)"""
    if "HARDCODED" in rule_id: return "CRITICAL_SECRET_LEAK"
    if any(k in rule_id for k in ["SHA1", "MD5", "DES"]): return "VULNERABLE (CLASSIC)"
    if any(k in rule_id for k in ["RSA", "ECC", "WEAK"]): return "VULNERABLE (QUANTUM)"
    if any(k in rule_id for k in ["KYBER", "DILITHIUM"]): return "PQC_READY"
    if "AES" in rule_id and "SAFE" in rule_id: return "SAFE (QUANTUM-RESISTANT)"
    return "UNKNOWN"

def generate_cbom_json(findings):
    """將掃描結果轉換為簡化的 CBOM 格式"""
    cbom_data = {
        "metadata": {
            "tool": "PQC Hybrid Auditor (Multi-Language)",
            "version": "2.0",
            "total_findings": len(findings),
            "timestamp": datetime.now().isoformat()
        },
        "cryptographic_assets": []
    }
    for finding in findings:
        asset_type = "ASYMMETRIC" if 'RSA' in finding['RuleID'] or 'ECC' in finding['RuleID'] else "SYMMETRIC/HASH"
        cbom_data['cryptographic_assets'].append({
            "asset_id": finding['RuleID'],
            "location": finding['Location'],
            "type": asset_type,
            "code_snippet": finding['CodeSnippet'],
            "risk_status": finding['Type'],
        })
    return cbom_data
