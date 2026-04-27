  #include <openssl/rsa.h>

// 測試 Alias 還原
using LegacyRSA = RSA_generate_key;

int main() {
    // 1. 弱金鑰測試：1024 bit (預期：B413_RSA_WEAK_SIZE)
    RSA_generate_key(1024, 65537, NULL, NULL);

    // 2. 安全金鑰測試：2048 bit (預期：B413_RSA)
    RSA_generate_key(2048, 65537, NULL, NULL);

    // 3. 別名還原測試：512 bit (預期：B413_RSA_WEAK_SIZE)
    LegacyRSA(512, 65537, NULL, NULL);

    // 4. 一般雜湊測試 (預期：B303)
    EVP_sha1();

    // 5. PQC 測試 (預期：B501_KYBER)
    OQS_KEM_kyber_768_new();

    // 硬編碼秘密測試
    const char* api_key = "AKIAJSIE1234567890EXAMPLE"; // 預期：B707_HARDCODED_AWS
    const char* user_password = "super_secret_password_123"; // 預期：B706_HARDCODED_PASSWORD
    const char* kyber_sk = "pqc_private_key_content_here..."; // 預期：B709_HARDCODED_PQC_SK
    const char* public_key = "this_is_safe_because_it_is_public"; // 預期：不應觸發 B702
    
    // 1. AES ECB 模式測試 (預期：B413_AES_WEAK)
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);

    // 2. 弱 ECC 曲線測試 (預期：B415_ECC_WEAK_CURVE)
    EC_KEY_new_by_curve_name("secp192k1");

    // 3. 安全 ECC 曲線測試 (預期：B413_ECC)
    EC_KEY_new_by_curve_name("prime256v1");

    return 0;
}
