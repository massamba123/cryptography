package asymetrique;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import symetrique.Utils;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class TestH2Partie {
    public static void main(String[] args) throws Exception{
        // Generation de KeyPairGenerator
        BouncyCastleProvider bc = new BouncyCastleProvider();
        Security.insertProviderAt(bc,1);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH","SunJCE");
        kpg.initialize(704);
        KeyPair aPair,bPair;
        // Generation de paire de clé
        aPair = kpg.generateKeyPair();
        bPair = kpg.generateKeyPair();
        /* Instance de KeyAgreement */
        KeyAgreement aka,bka;
        aka = KeyAgreement.getInstance("DH","BC");
        bka = KeyAgreement.getInstance("DH","BC");
        // initialisation de KeyAgreement
        aka.init(aPair.getPrivate());
        bka.init(bPair.getPrivate());
        // Echange des parametres publiques
        aka.doPhase(bPair.getPublic(),true);
        bka.doPhase(aPair.getPublic(),true);
        // Generation de la cle partagé
        SecretKey ska,skb;
        byte[] secretA = aka.generateSecret();
        byte[] secretB = aka.generateSecret();
        ska = aka.generateSecret("AES");
        skb = aka.generateSecret("AES");
        System.out.println("ska : "+ Utils.toHex(ska.getEncoded()) +"\nskab : "+Utils.toHex(skb.getEncoded()));
    }
}
