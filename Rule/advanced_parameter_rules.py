# ==============================================================================
# 類別: 進階參數與配置檢查 (Advanced Parameter Validation)
# ==============================================================================

# 1. ECC 曲線強度檢查 (Curve Strength)
"B415_ECC_WEAK_CURVE": {
    "category": "PARAMETER_CHECK",
    "type": "WEAK_ECC_CURVE",
    "message": "偵測到使用強度不足的橢圓曲線 (如 P-192, secp160r1)。",
    "fix": "請使用 NIST P-256 (SECP256R1) 或更高強度的曲線。PQC 遷移建議：使用 Hybrid 模式。",
    "pqc_status": "VULNERABLE"
},

# 2. PBKDF2 迭代次數檢查 (Iteration Count)
"B703_WEAK_KDF_ITERATIONS": {
    "category": "PARAMETER_CHECK",
    "type": "WEAK_KDF_ITERATION_COUNT",
    "message": "PBKDF2 迭代次數過低 (< 600,000)。",
    "fix": "根據 OWASP 建議，PBKDF2-HMAC-SHA256 至少需要 600,000 次迭代以抵禦 GPU 破解。",
    "pqc_status": "IMPLEMENTATION_FLAW"
},

# 3. Salt (鹽值) 長度檢查
"B710_SHORT_SALT": {
    "category": "PARAMETER_CHECK",
    "type": "INSUFFICIENT_SALT_LENGTH",
    "message": "Salt 長度不足 (小於 16 bytes / 128 bits)。",
    "fix": "Salt 應該至少為 16 bytes (128 bits) 的隨機資料，以防止彩虹表攻擊。",
    "pqc_status": "IMPLEMENTATION_FLAW"
},

# 4. GCM Nonce 長度檢查 (AES-GCM 特定風險)
"B416_GCM_NONCE_LENGTH": {
    "category": "PARAMETER_CHECK",
    "type": "RISKY_GCM_NONCE_LENGTH",
    "message": "AES-GCM 模式使用了非標準長度的 Nonce (!= 12 bytes)。",
    "fix": "NIST 強烈建議 GCM Nonce 長度固定為 96 bits (12 bytes) 以避免額外的 GHASH 運算風險。",
    "pqc_status": "IMPLEMENTATION_FLAW"
}
