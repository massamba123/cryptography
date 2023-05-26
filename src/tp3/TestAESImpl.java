package tp3;

import symetrique.Utils;

import javax.crypto.*;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class TestAESImpl implements TestAES {

    @Override
    public SecretKey genKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    @Override
    public void saveKey(SecretKey key,String filname) throws IOException {
        FileOutputStream file = new FileOutputStream(filname);
        ObjectOutputStream outputStream = new ObjectOutputStream(file);
        outputStream.write(key.getEncoded());
        outputStream.close();
        System.out.println("file : "+file);
    }

    @Override
    public SecretKey getKey(String filname) throws IOException, ClassNotFoundException {
        FileInputStream fileInputStream = new FileInputStream(filname);
        ObjectInputStream in = new ObjectInputStream(fileInputStream);
        return new SecretKey() {
            @Override
            public String getAlgorithm() {
                return "AES";
            }

            @Override
            public String getFormat() {
                return "RAW";
            }

            @Override
            public byte[] getEncoded() {
                try {
                    return in.readAllBytes();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @Override
    public byte[] crypt(String message) throws NoSuchPaddingException, NoSuchAlgorithmException {
        return new byte[0];
    }
    @Override
    public String decrypt(byte[] cipherText) {
        return null;
    }
    public static void main(String[] args) throws Exception {
        TestAES testAES = new TestAESImpl();
        //SecretKey key = testAES.genKey();
        //System.out.println("key avant: "+ Utils.toHex(key.getEncoded()));
        //testAES.saveKey(key);
        SecretKey key1 = testAES.getKey("aes.key");
        System.out.println("key apres: "+ Utils.toHex(key1.getEncoded()));
    }
}
