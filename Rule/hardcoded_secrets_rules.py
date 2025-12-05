# ==============================================================================
# 類別: 硬編碼與機密管理 (Hardcoded Secrets & Credentials)
# ==============================================================================

# 1. 通用硬編碼密鑰 (General Keys)
"B702_HARDCODED_KEY": {
    "category": "HARDCODED",
    "type": "HARDCODED_SECRET_KEY",
    "message": "偵測到疑似硬編碼的加密金鑰 (變數名包含 key/secret 且值為字串常量)。",
    "fix": "絕對禁止在程式碼中寫死金鑰。請改用環境變數 (os.getenv)、Vault 或 KMS。",
    "pqc_status": "CRITICAL_RISK"
},

# 2. 硬編碼密碼 (Passwords)
"B706_HARDCODED_PASSWORD": {
    "category": "HARDCODED",
    "type": "HARDCODED_PASSWORD",
    "message": "偵測到疑似硬編碼的密碼 (變數名包含 password/passwd/pwd)。",
    "fix": "請勿將密碼儲存在原始碼中。請使用設定檔或機密管理服務。",
    "pqc_status": "CRITICAL_RISK"
},

# 3. 硬編碼 AWS 憑證 (AWS Credentials) - 常見錯誤
"B707_HARDCODED_AWS": {
    "category": "HARDCODED",
    "type": "HARDCODED_CLOUD_CREDENTIAL",
    "message": "偵測到硬編碼的 AWS Access Key 或 Secret Key。",
    "fix": "請使用 AWS IAM Role、~/.aws/credentials 檔案或環境變數。",
    "pqc_status": "CRITICAL_RISK"
},

# 4. 硬編碼 API Token/Bearer Token
"B708_HARDCODED_TOKEN": {
    "category": "HARDCODED",
    "type": "HARDCODED_API_TOKEN",
    "message": "偵測到疑似硬編碼的 API Token 或 Bearer Token。",
    "fix": "Token 應動態生成或從安全儲存區載入。",
    "pqc_status": "HIGH_RISK"
},

# 5. PQC 私鑰硬編碼 (針對 Kyber/Dilithium) - PQC 特有
"B709_HARDCODED_PQC_SK": {
    "category": "HARDCODED",
    "type": "HARDCODED_PQC_PRIVATE_KEY",
    "message": "偵測到疑似 PQC 私鑰 (Variable name hints sk/secret_key) 的硬編碼賦值。",
    "fix": "PQC 私鑰體積較大，若寫死在程式碼中會造成嚴重的洩漏風險與維護困難。",
    "pqc_status": "CRITICAL_RISK"
}
