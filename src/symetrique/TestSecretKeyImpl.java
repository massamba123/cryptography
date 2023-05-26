package symetrique;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;

public class TestSecretKeyImpl implements TestSecretKey {
    public static SecretKey genKey(String algorithm, int taille) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(algorithm);
        kg.init(taille);
        return kg.generateKey();
    }
    public static void saveKey(SecretKey key,String path) throws Exception{
        FileOutputStream fileOutputStream = new FileOutputStream(path);
        ObjectOutputStream out = new ObjectOutputStream(fileOutputStream);
        out.writeObject(key);
        out.close();
        fileOutputStream.close();
        String outPut = "Cle d'Algo "+key.getAlgorithm()+" bien sauvegardé";
        System.out.println(outPut);
    }
    public static SecretKey getKey(String path) throws Exception{
        FileInputStream in = new FileInputStream(path);
        ObjectInputStream file = new ObjectInputStream(in);
        SecretKey sk = (SecretKey) file.readObject();
        file.close();
        in.close();
        return sk;
    }

    public static void main(String[] args)  throws Exception{
        SecretKey sk = TestSecretKeyImpl.genKey("AES",128);
        String path = "/home/massamba/Bureau/M2TDSI/JAVA CRYPTO/key/";
        TestSecretKeyImpl.saveKey(sk,path+"cleAes.txt");
        SecretKey key = TestSecretKeyImpl.getKey(path+"cleAes.txt");
        if (Arrays.equals(sk.getEncoded(), key.getEncoded())){
            System.out.println("Cle identiques");
        }
        else {
            System.out.println("Cle non identiques");
        }
    }
}
