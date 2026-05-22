import ast
import json
from datetime import datetime

# --- PQC 知識庫與修復建議 (PQC_KNOWLEDGE_BASE) ---
PQC_KNOWLEDGE_BASE = {
    # 弱雜湊 (Priority Fixes)
    "B303": {"type": "WEAK_HASH_SHA1", "message": "使用了 SHA1 雜湊算法。", "fix": "替換為 hashlib.sha256/sha3，SHA1 對碰撞攻擊是脆弱的。"},
    "B324": {"type": "WEAK_HASH_MD5", "message": "使用了 MD5 雜湊算法。", "fix": "必須移除 MD5，替換為 SHA256。"},
    # 弱加密算法 (Priority Fixes)
    "B304": {"type": "WEAK_CIPHER_DES", "message": "使用了 DES/3DES 弱加密算法。", "fix": "停用 DES/3DES，改用 AES-256 GCM 模式。"},
    # 量子脆弱資產與使用樣式 (PQC/AES)
    "B413_RSA": {"type": "PQC_TARGET_RSA", "message": "發現 RSA 密鑰生成。", "fix": "量子脆弱：考慮替換為 CRYSTALS-Kyber (KEM) 或 Dilithium (Signature)。"},
    "B413_AES_WEAK": {"type": "WEAK_CIPHER_MODE", "message": "使用了不安全的 AES/ECB 模式。", "fix": "替換為 AES-256 GCM 或 CCM 模式，確保認證性。"},
    "B413_AES_SAFE": {"type": "TRADITIONAL_AES_ASSET", "message": "使用了 AES 加密資產。", "fix": "這是一個抗量子資產。請確保 IV/Nonce 是正確生成的。"},
    "B413_RSA_WEAK_SIZE": {
        "type": "WEAK_ASSET_RSA", 
        "message": "發現 RSA 密鑰長度小於 2048 bits，對暴力破解脆弱。", 
        "fix": "將密鑰長度至少增加到 2048/4096 bits，並規劃 PQC 遷移。"
    },
    # CBC/CFB 模式 IV 缺失 (使用樣式風險)
    "B413_IV_WEAK": {
        "type": "WEAK_IV_NONCE", 
        "message": "在 CBC/CFB 模式中，未偵測到 IV/Nonce 參數，易受重放攻擊。", 
        "fix": "必須使用 os.urandom (Python) 或 SecureRandom (Java) 創建隨機 IV。"
    },
    # 量子脆弱的 ECC
    "B413_ECC": { 
        "type": "PQC_TARGET_ECC", 
        "message": "發現 ECC/ECDSA/ECDH 橢圓曲線加密資產。", 
        "fix": "核心量子脆弱資產，建議替換為 CRYSTALS-Dilithium/Falcon。"
    },
	# 硬編碼偵測
	"B105_HARDCODED_SECRET": {
    "type": "SECRET_LEAKAGE",
    "message": "發現硬編碼密鑰，可能導致密鑰洩露，影響 PQC 遷移後的安全性。",
    "fix": "將密鑰儲存於環境變數或專門的密鑰管理器中。"
	},
    # --- PQC 正面識別 (PQC Ready) ---
    "B501_KYBER": {"type": "PQC_KEM_ML_KEM", "message": "發現 NIST 標準 PQC 算法：ML-KEM (Kyber)。", "fix": "PQC READY。請確保實作符合 FIPS 203 標準。"},
    "B502_DILITHIUM": {"type": "PQC_SIGN_ML_DSA", "message": "發現 NIST 標準 PQC 算法：ML-DSA (Dilithium)。", "fix": "PQC READY。請確保實作符合 FIPS 204 標準。"},
    # --- [HARDCORE] 硬編碼與機密管理 ---
    "B702_HARDCODED_KEY": {"type": "HARDCODED_SECRET_KEY", "message": "偵測到疑似硬編碼的加密金鑰。", "fix": "絕對禁止在程式碼中寫死金鑰。請改用環境變數或 KMS。"},
    "B706_HARDCODED_PASSWORD": {"type": "HARDCODED_PASSWORD", "message": "偵測到疑似硬編碼的密碼。", "fix": "請勿將密碼儲存在原始碼中。"},
    "B707_HARDCODED_AWS": {"type": "HARDCODED_CLOUD_CREDENTIAL", "message": "偵測到硬編碼 AWS Key (AKIA...)。", "fix": "使用 IAM Role。"},
    "B708_HARDCODED_TOKEN": {"type": "HARDCODED_API_TOKEN", "message": "偵測到疑似硬編碼 API Token。", "fix": "動態生成 Token。"},
    "B709_HARDCODED_PQC_SK": {"type": "HARDCODED_PQC_PRIVATE_KEY", "message": "偵測到疑似 PQC 私鑰硬編碼。", "fix": "PQC 私鑰極為敏感。"},
    "B701_WEAK_RNG": {"type": "WEAK_RANDOM_SOURCE", "message": "使用弱亂數 (random)。", "fix": "改用 os.urandom。"},

    # --- [ADVANCE] 進階參數檢查 ---
    "B415_ECC_WEAK_CURVE": {"type": "WEAK_ECC_CURVE", "message": "弱橢圓曲線 (如 P-192)。", "fix": "使用 NIST P-256 以上。"},
    "B703_WEAK_KDF_ITERATIONS": {"type": "WEAK_KDF_ITERATION_COUNT", "message": "PBKDF2 迭代次數過低。", "fix": "建議 > 600,000 次。"},
    "B710_SHORT_SALT": {"type": "INSUFFICIENT_SALT_LENGTH", "message": "Salt 長度不足。", "fix": "Salt 應 > 16 bytes。"},
    "B416_GCM_NONCE_LENGTH": {"type": "RISKY_GCM_NONCE_LENGTH", "message": "GCM Nonce 非 12 bytes。", "fix": "固定為 12 bytes。"},
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