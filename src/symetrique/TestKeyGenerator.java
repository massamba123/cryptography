package symetrique;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.util.Arrays;

public class TestKeyGenerator {
    public static void main(String[] args) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES","BC");

        kg.init(256);
        SecretKey sk = kg.generateKey();
        String out = "Cle Symetrique:\n Valeur = "+ Utils.toHex(sk.getEncoded())
                +"\n Algorithme = "+sk.getAlgorithm()+" \n Format = "+
                sk.getFormat()+"\n Provider = "+kg.getProvider();
        System.out.println(out);
    }
}
