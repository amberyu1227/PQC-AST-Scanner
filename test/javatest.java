import java.security.MessageDigest;
import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.SecureRandom;

public class TestCryptoFull {

    public void init() throws Exception {
        
        // --- 1. 量子脆弱的非對稱加密 (PQC 目標) ---
        
        // B413_RSA: RSA 盤點
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA"); 
        
        // B413_ECC: ECC 盤點
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC"); 
        
        // --- 2. 弱加密與雜湊 (優先修復) ---
        
        // B303: 弱雜湊 SHA1
        MessageDigest sha1Digest = MessageDigest.getInstance("SHA1");

        // B304: 弱加密 DES
        Cipher desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding"); 
        
        // B413_AES_WEAK: AES/ECB 模式
        Cipher ecbCipher = Cipher.getInstance("AES/ECB/NoPadding"); 

        // B413_AES_SAFE: AES/GCM 模式 (可接受的資產)
        Cipher safeAesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    }
}