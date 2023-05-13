import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;

public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("Hello Java Cryptography!");

        KeyPair keypair  = Asymmetric.generateRSAKkeyPair();
        System.out.println("A Key Pair Generated for Cryptography by RSA Algorithm... ");
        System.out.println("A RSA Public Key is= "+ DatatypeConverter.printHexBinary(keypair.getPublic().getEncoded()));
        System.out.println("A RAS Private Key is= "+ DatatypeConverter.printHexBinary(keypair.getPrivate().getEncoded()));


        System.out.println("We Want to encrypt  and Decrypt 'Jalal Hosseini' with  RAS private and public key ... ");

        byte[] encryptedText =  Asymmetric.doEncryption("Jalal Hosseini",keypair.getPrivate());
        System.out.println("Encrypted Text for 'Jalal Hosseini' by RAS is = " + DatatypeConverter.printHexBinary(encryptedText));

        String decryptedText =  Asymmetric.doDecrypte(encryptedText,keypair.getPublic());
        System.out.println("Decryptd  Text for "+DatatypeConverter.printHexBinary(encryptedText) +" BY RSA is = " + decryptedText);

        System.out.println("We Want to Encrypte and Decrypte AES 256 Algorithm... ");
        System.out.println("First Step is create Symmetric Key");
        SecretKey symmetricKey = SymmetricAES.createAESKey();
        System.out.println("The Symmetric Key is :"+ DatatypeConverter.printHexBinary(symmetricKey.getEncoded()));
        byte[] initVector = SymmetricAES.createInitializationVector();
        byte[] encryptedTextByAES256 = SymmetricAES.do_Encryption("Jalal ",symmetricKey,initVector);
        System.out.println("Encrypted Text for 'Jalal Hosseini' by AES is =" + DatatypeConverter.printHexBinary(encryptedTextByAES256));

        String  decryptedTextByAES256 = SymmetricAES.do_Decryption(encryptedTextByAES256,symmetricKey,initVector);
        System.out.println("Decrypted Text for "+DatatypeConverter.printHexBinary(encryptedTextByAES256)+" by AES is =" + decryptedTextByAES256);


    }
}