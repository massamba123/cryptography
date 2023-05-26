package symetrique;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.Security;
import java.util.Scanner;

public class TestPBE {
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.println("Saisir le password,le salt et l'ieration");
        char[] password = sc.nextLine().toCharArray();
        byte[] salt = sc.nextLine().getBytes();
        int iteration = sc.nextInt();
        BouncyCastleProvider pd = new BouncyCastleProvider();
        Security.insertProviderAt(pd,1);
        PBEKeySpec pbe = new PBEKeySpec(password,salt,iteration);
        //algorithm  = PBEWithSHA256And128BITAES-CBC-BC
        //algorithm = PBEWithMD5AndAES
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithSHA256And128BITAES-CBC-BC");
        SecretKey sk = skf.generateSecret(pbe);
        String out = "Cle PBE:\n Valeur = "+ Utils.toHex(sk.getEncoded())
                +"\n Algorithme = "+sk.getAlgorithm()+" \n Format = "+
                sk.getFormat()+"\n Taille : "+sk.getEncoded().length*8+"\n Provider = "+skf.getProvider();
        System.out.println(out);
    }
}
