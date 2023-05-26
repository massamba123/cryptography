package asymetrique;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import symetrique.Utils;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.util.Scanner;

public class TestAsymetrique {
    public static KeyPair genKey(String algorithm,int taille) throws Exception{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm,"BC");
        kpg.initialize(taille,new SecureRandom());
        return kpg.generateKeyPair();
    }
    public static void saveKeyPair(KeyPair keyPair,String path) throws Exception {
        String pathKeyPriv = path+"priv.txt";
        String pathKeyPub = path+"pub.txt";
        FileOutputStream fileOutputStream = new FileOutputStream(pathKeyPub);
        ObjectOutputStream out = new ObjectOutputStream(fileOutputStream);
        out.writeObject(keyPair.getPublic());
        out.close();
        fileOutputStream.close();
        fileOutputStream = new FileOutputStream(pathKeyPriv);
        out = new ObjectOutputStream(fileOutputStream);
        out.writeObject(keyPair.getPrivate());
        out.close();
        fileOutputStream.close();
        String outPut = "Cle Public et Privée d'Algo"+keyPair.getPublic().getAlgorithm()+" bien sauvegardé";
        System.out.println(outPut);
    }
    public static PublicKey getPublicKey(String path) throws Exception{
        FileInputStream in = new FileInputStream(path);
        ObjectInputStream file = new ObjectInputStream(in);
        PublicKey pub = (PublicKey) file.readObject();
        file.close();
        in.close();
        return pub;
    }
    public static PrivateKey getPrivateKey(String path) throws Exception{
        FileInputStream in = new FileInputStream(path);
        ObjectInputStream file = new ObjectInputStream(in);
        PrivateKey priv = (PrivateKey) file.readObject();
        file.close();
        in.close();
        return priv;
    }

    public static void main(String[] args) throws Exception{
        BouncyCastleProvider bc = new BouncyCastleProvider();
        Security.insertProviderAt(bc,1);
        String path = "/home/massamba/Bureau/M2TDSI/JAVA CRYPTO/Cours-TP_Crypto-Java/key/";
        System.out.println("Entrer l'algorithme de chiffrement \n");
        Scanner scanner = new Scanner(System.in);
        String algo = scanner.nextLine();
        System.out.println("Entrer la taille de la clé chiffrement \n");
        int taille = scanner.nextInt();
        KeyPair keyPair = TestAsymetrique.genKey(algo,taille);
        TestAsymetrique.saveKeyPair(keyPair,path);
        PrivateKey privateKey = TestAsymetrique.getPrivateKey(path+"priv.txt");
        PublicKey publicKey = TestAsymetrique.getPublicKey(path+"pub.txt");
        String out = "Cle privée : \n"+
                "Algorithme : "+privateKey.getAlgorithm()+"\n"+
                "Valeur : "+ Utils.toHex(privateKey.getEncoded());
        System.out.println(out);
        out = "\n Cle publique : \n"+
                "Algorithme : "+publicKey.getAlgorithm()+"\n"+
                "Valeur : "+ Utils.toHex(publicKey.getEncoded());
        System.out.println(out);
    }
}
