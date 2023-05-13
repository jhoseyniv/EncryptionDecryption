import AsymetricRSA.Asymmetric;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;

public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("Hello Java Cryptography!");

        KeyPair keypair  = Asymmetric.generateRSAKkeyPair();
        System.out.println("A Key Pair Generated for Cryptography by RSA Algorithm... ");
        System.out.println("A Public Key is= "+ DatatypeConverter.printHexBinary(keypair.getPublic().getEncoded()));
        System.out.println("A Priave Key is= "+ DatatypeConverter.printHexBinary(keypair.getPrivate().getEncoded()));

    }
}