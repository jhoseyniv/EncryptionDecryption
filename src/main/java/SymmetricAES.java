import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class SymmetricAES {
    public static final String AES = "AES";
    // We are using a Block cipher(CBC mode)
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5PADDING";


    // Function to create a secret key
    public static SecretKey createAESKey()
            throws Exception
    {

        // Creating a new instance of
        // SecureRandom class.
        SecureRandom securerandom = new SecureRandom();

        // Passing the string to
        // KeyGenerator
        KeyGenerator keygenerator = KeyGenerator.getInstance(AES);

        // Initializing the KeyGenerator
        // with 256 bits.
        keygenerator.init(256, securerandom);
        SecretKey key = keygenerator.generateKey();
        return key;
    }
    // Function to initialize a vector
    // with an arbitrary value
    public static byte[] createInitializationVector()
    {

        // Used with encryption
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }


    // This function takes plaintext,
    // the key with an initialization
    // vector to convert plainText
    // into CipherText.
    public static byte[] do_Encryption(String plainText, SecretKey secretKey,byte[] initializationVector)
            throws Exception
    {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);

        IvParameterSpec ivParameterSpec = new IvParameterSpec( initializationVector);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey,ivParameterSpec);

        return cipher.doFinal(plainText.getBytes());
    }


    // This function performs the  reverse operation of the do_Encryption function.
    // It converts ciphertext to  the plaintext using the key.
    public static String do_Decryption( byte[] cipherText,SecretKey secretKey,byte[] initializationVector) throws Exception
    {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init( Cipher.DECRYPT_MODE,secretKey,ivParameterSpec);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }
}
