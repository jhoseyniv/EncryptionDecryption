package AsymetricRSA;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Asymmetric {
    private static final String RSA = "RSA";
    // Generating public and private keys
    // using RSA algorithm.
    public static KeyPair generateRSAKkeyPair()
            throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);

        keyPairGenerator.initialize(512, secureRandom);

        return keyPairGenerator.generateKeyPair();
    }
    public static byte[] doEncryption(String plainText,PrivateKey privateKey) throws Exception
    {
        Cipher cipher= Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encrypetedText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return encrypetedText;
    }
    public static String doDecrypte(byte[] cipherText, PublicKey publicKey) throws Exception {
        Cipher cipher= Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedText = cipher.doFinal(cipherText);
        return new String(decryptedText);

    }


}
