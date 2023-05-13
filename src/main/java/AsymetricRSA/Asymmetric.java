package AsymetricRSA;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

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

}
