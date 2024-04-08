package com.talenthub.auth.tool;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

@Service
public class CryptoUtil {
    @Value("${crypto.secretKey}")
    private String SECRET_KEY;

    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";

    private Key generateKey() throws Exception {
        return new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");
    }

    public String encrypt(String data)  {
        try{
            Key key = generateKey();
            Cipher c = Cipher.getInstance(ALGORITHM);
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encVal = c.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encVal);
        }catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    public String decrypt(String encryptedData) {
        try {
            Key key = generateKey();
            Cipher c = Cipher.getInstance(ALGORITHM);
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decodedValue = Base64.getDecoder().decode(encryptedData);
            byte[] decVal = c.doFinal(decodedValue);
            return new String(decVal);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
