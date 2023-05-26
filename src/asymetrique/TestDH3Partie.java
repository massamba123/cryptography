package asymetrique;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import symetrique.Utils;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class TestDH3Partie {
    public static void main(String[] args) throws Exception {
        // Generation de KeyPairGenerator
        BouncyCastleProvider bcc = new BouncyCastleProvider();
        Security.insertProviderAt(bcc,1);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH","SunJCE");
        kpg.initialize(704);
        KeyPair aPair,bPair,cPair;
        // Generation de paire de clé
        aPair = kpg.generateKeyPair();
        bPair = kpg.generateKeyPair();
        cPair = kpg.generateKeyPair();
        /* Instance de KeyAgreement */
        KeyAgreement aka,bka,cka;
        aka = KeyAgreement.getInstance("DH","BC");
        bka = KeyAgreement.getInstance("DH","BC");
        cka = KeyAgreement.getInstance("DH","BC");
        // initialisation de KeyAgreement
        aka.init(aPair.getPrivate());
        bka.init(bPair.getPrivate());
        cka.init(cPair.getPrivate());
        // Echange des parametres publiques premiere phase
        Key ba =  aka.doPhase(bPair.getPublic(),false);
        Key bc = bka.doPhase(cPair.getPublic(),false);
        Key ca = cka.doPhase(aPair.getPublic(),false);
        // recuperation des clé
        // Echange des parametres publiques deuxieme phase
        aka.doPhase(bc,true);
        bka.doPhase(ca,true);
        cka.doPhase(ba,true);
        // Generation de la cle partagé
        byte[] secretA = aka.generateSecret();
        byte[] secretB = bka.generateSecret();
        byte[] secretC = cka.generateSecret();
        SecretKey ska,skb,skc;
        ska = aka.generateSecret("AES");
        skb = bka.generateSecret("AES");
        skc = cka.generateSecret("AES");
        System.out.println("ska : "+ Utils.toHex(secretA) +"\nskb : "+Utils.toHex(secretB)+
                "\nskb : "+Utils.toHex(secretC));
    }
}
