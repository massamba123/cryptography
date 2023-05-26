package asymetrique;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;

public class TestDSAP {
    public static void main(String[] args) throws Exception{
        BouncyCastleProvider bc = new BouncyCastleProvider();
        Security.insertProviderAt(bc,1);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA","BC");
        kpg.initialize(1024);
        KeyPair kp =  kpg.generateKeyPair();
        DSAPublicKey pub1 = (DSAPublicKey) kp.getPublic();
        DSAPrivateKey priv1 = (DSAPrivateKey) kp.getPrivate();
        BigInteger p,q,g,x,y;
        x = priv1.getX();
        y = pub1.getY();
        p = pub1.getParams().getP();
        q = pub1.getParams().getQ();
        g = pub1.getParams().getG();
        DSAPublicKeySpec pubSpec = new DSAPublicKeySpec(y,p,q,g);
        DSAPrivateKeySpec privSpec = new DSAPrivateKeySpec(x,p,q,g);
        KeyFactory kf = KeyFactory.getInstance("DSA","BC");
        DSAPublicKey pub2 = (DSAPublicKey) kf.generatePublic(pubSpec);
        DSAPrivateKey priv2 = (DSAPrivateKey) kf.generatePrivate(privSpec);
    }
}
