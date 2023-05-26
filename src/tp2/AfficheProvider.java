package tp2;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.Security;
public class AfficheProvider {
	
	public static void main(String []args){
		System.out.println(System.getProperty("java.version"));
		BouncyCastleProvider pd = new BouncyCastleProvider();
		Security.insertProviderAt(pd,1);
		Provider []p = Security.getProviders();
		System.out.println("Nombre providers =" +p.length);
		for(int i = 0; i < p.length; i++) {
			System.out.println(p[i].getName());
		}
	}
}
