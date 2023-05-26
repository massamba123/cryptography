package tp3;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public interface TestAES {
    public SecretKey genKey() throws NoSuchAlgorithmException, NoSuchProviderException;
    public void saveKey(SecretKey key,String filname) throws IOException;
    public SecretKey getKey(String filname) throws IOException, ClassNotFoundException;
    public byte[] crypt(String message) throws NoSuchPaddingException, NoSuchAlgorithmException;
    public String decrypt(byte[] cipherText);
}
