package asymetrique;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import symetrique.Utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class TestRSA {
    public static void main(String[] args) throws Exception {
        BouncyCastleProvider bc = new BouncyCastleProvider();
        Security.insertProviderAt(bc,1);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA","BC");
        kpg.initialize(2048,new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        RSAPublicKey pubRSA = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey privRSA = (RSAPrivateKey) kp.getPrivate();
        String out = "Clé publique "+ Utils.toHex(pubRSA.getEncoded());
        System.out.println(out);
        out = "Clé privée "+ Utils.toHex(privRSA.getEncoded());
        System.out.println(out);
    }
}
