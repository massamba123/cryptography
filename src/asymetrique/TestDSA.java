package asymetrique;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class TestDSA {
    public static KeyPair genKey(String algorithm,int taille) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm,"BC");
        kpg.initialize(taille,new SecureRandom());
        return kpg.generateKeyPair();
    }
    public static DSAPublicKey getPubKeyWithSpecifications(BigInteger y,BigInteger p,BigInteger q,BigInteger g) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("DSA","BC");
        DSAPublicKeySpec dsaPkeySpec = new DSAPublicKeySpec(y, p, q, g);
        return (DSAPublicKey) factory.generatePublic(dsaPkeySpec);
    }
    public static DSAPrivateKey getPrivKeyWithSpecifications(BigInteger x,BigInteger p,BigInteger q,BigInteger g)throws Exception{
        KeyFactory factory = KeyFactory.getInstance("DSA","BC");
        DSAPrivateKeySpec dsaPrivateKeySpec = new DSAPrivateKeySpec(x, p, q, g);
        return (DSAPrivateKey) factory.generatePrivate(dsaPrivateKeySpec);
    }
    public static DSAPublicKey genPubKeyWithEncodedKey(byte[] pubEncoded)throws Exception{
        KeyFactory kf = KeyFactory.getInstance("DSA","BC");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pubEncoded);
        return (DSAPublicKey) kf.generatePublic(x509EncodedKeySpec);
    }
    public static DSAPrivateKey genPrivKeyWithEncodedKey(byte[] privEncoded) throws Exception{
        KeyFactory kf = KeyFactory.getInstance("DSA","BC");
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privEncoded);
        return (DSAPrivateKey) kf.generatePrivate(pkcs8EncodedKeySpec);
    }
    public static void main(String[] args) throws Exception{
        BouncyCastleProvider bc = new BouncyCastleProvider();
        Security.insertProviderAt(bc,1);
        KeyPair kp = TestDSA.genKey("DSA",1024);
        DSAPublicKey dsaPublicKey = (DSAPublicKey) kp.getPublic();
        DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) kp.getPrivate();
        BigInteger x,y,p,q,g;
        x = dsaPrivateKey.getX();
        y = dsaPublicKey.getY();
        p = dsaPublicKey.getParams().getP();
        q = dsaPublicKey.getParams().getQ();
        g = dsaPublicKey.getParams().getG();

        String out = "Algorithme : "+kp.getPublic().getAlgorithm()+
                "\n---------------------Parametres DSA--------------------------------------------------------------"+
                "\nP : "+p+
                "\nQ : "+q+
                "\nG : "+g+
                "\n----------------Cle publique------------------------------------------------------------------------"+
                "\nY : "+y+
                "\n----------------Cle privée----------------------------------------------------------------------------"+
                "\nX : "+x;
        System.out.println(out);
        DSAPrivateKey dsaprivSpec1 = TestDSA.getPrivKeyWithSpecifications(x,p,q,g);
        DSAPublicKey dsapubSpec1 = TestDSA.getPubKeyWithSpecifications(y,p,q,g);
        System.out.println("----------------------------------------------------------------------------------------------");
        System.out.println("------Fabrication avec specification---------------------------------------------------------------");
        System.out.println("Comparaison clé privée : "+Arrays.equals(dsaPrivateKey.getEncoded(),dsaprivSpec1.getEncoded()));
        System.out.println("Comparaison clé publique : "+Arrays.equals(dsaPublicKey.getEncoded(),dsapubSpec1.getEncoded()));
        System.out.println("-----------------------------------------------------------------------------------------------------");
        System.out.println("------Fabrication avec encodage---------------------------------------------------------------------");
        DSAPublicKey dsapubEncoded = TestDSA.genPubKeyWithEncodedKey(dsaPublicKey.getEncoded());
        DSAPrivateKey dsaprivEncoded = TestDSA.genPrivKeyWithEncodedKey(dsaPrivateKey.getEncoded());
        System.out.println("Comparaison clé privée : "+Arrays.equals(dsaPrivateKey.getEncoded(),dsaprivEncoded.getEncoded()));
        System.out.println("Comparaison clé publique : "+Arrays.equals(dsaPublicKey.getEncoded(),dsapubEncoded.getEncoded()));
        System.out.println("-----------------------------------------------------------------------------------------------------");
    }
}
