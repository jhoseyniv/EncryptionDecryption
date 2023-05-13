import AsymetricRSA.Asymmetric;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;

public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("Hello Java Cryptography!");

        KeyPair keypair  = Asymmetric.generateRSAKkeyPair();
        System.out.println("A Key Pair Generated for Cryptography by RSA Algorithm... ");
        System.out.println("A Public Key is= "+ DatatypeConverter.printHexBinary(keypair.getPublic().getEncoded()));
        System.out.println("A Private Key is= "+ DatatypeConverter.printHexBinary(keypair.getPrivate().getEncoded()));


        System.out.println("We Want to encrypt  and Decrypt 'Jalal Hosseini' with private and public key ... ");

        byte[] encryptedText =  Asymmetric.doEncryption("Jalal Hosseini",keypair.getPrivate());
        System.out.println("Encrypted Text for 'Jalal Hosseini' is = " + DatatypeConverter.printHexBinary(encryptedText));

        String decryptedText =  Asymmetric.doDecrypte(encryptedText,keypair.getPublic());
        System.out.println("Decryptd  Text for "+DatatypeConverter.printHexBinary(encryptedText) +" is = " + decryptedText);


    }
}