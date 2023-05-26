package asymetrique;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.DHUtil;
import symetrique.Utils;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.interfaces.DHPrivateKey;
import java.security.*;
import java.util.Arrays;

public class TestDiffieHelman {
    static class Partie {
        private KeyPair keyPair;
        private KeyAgreement keyAgreement;
        Partie() throws Exception {
            keyPair = KeyPairGenerator.getInstance("DiffieHellman","SunJCE").generateKeyPair();
            keyAgreement = KeyAgreement.getInstance("DiffieHellman","BC");
            keyAgreement.init(keyPair.getPrivate());
        }
        PublicKey getPublicKey() {
            return keyPair.getPublic();
        }

        Key sendPublicKey(PublicKey key) throws Exception {
           return keyAgreement.doPhase(key, false);
        }
        void receivePublicKey(Key key) throws Exception {
            keyAgreement.doPhase(key, true);
        }
        void afficheSecret() {
            byte[] secret = keyAgreement.generateSecret();
            System.out.println(Utils.toHex(secret));
        }
        byte[] getGetClePartage(){
            return keyAgreement.generateSecret();
        }
    }
    public static void main(String[] args) throws Exception{
        BouncyCastleProvider bcc = new BouncyCastleProvider();
        Security.insertProviderAt(bcc,1);
        Partie alice = new Partie();
        Partie bob = new Partie();
        Partie charlie = new Partie();

        // Alice and Bob echanege leur cle publique premiere phase
        Key ab =alice.sendPublicKey(bob.getPublicKey());
        Key bc =bob.sendPublicKey(charlie.getPublicKey());
        Key ca = charlie.sendPublicKey(alice.getPublicKey());
        // Alice and Bob echanege leur cle publique deuxieme phase
        alice.receivePublicKey(bc);
        bob.receivePublicKey(ca);
        charlie.receivePublicKey(ab);
        // Now both parties can calculate a shared secret:
        byte[] share1 = alice.getGetClePartage();
        byte[] share2 = bob.getGetClePartage();
        byte[] share3 = charlie.getGetClePartage();
        System.out.println("----------comparaison----------------");
        System.out.println("A -> B : "+Arrays.equals(share1,share2)+"\nB -> C : "+Arrays.equals(share2,share3)
        +"\nC - > A: "+Arrays.equals(share3,share1));
        System.out.println("-------------------------------------------------------\n");
        System.out.println("comparaison : "+ Arrays.equals(share1,share2));
        alice.afficheSecret();
        bob.afficheSecret();
        charlie.afficheSecret();
    }
}
