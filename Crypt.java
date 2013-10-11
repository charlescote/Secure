import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;


public class Crypt
{
	
	private SecretKeySpec sec_key_spec;
	private Cipher sec_cipher;
	private Hash digestCreator; 
	
	private byte[] converted;
	
	
	public Crypt (byte[] inFile, byte[] seed, int mode) throws Exception {
		keyGenerator(seed);
		converted = aes_crypt(inFile, mode);
	}
		
		
	private void keyGenerator(byte[] seed) {
		byte[] key;
		byte[] key128;
	
		//generates key
		digestCreator = new Hash(seed);
		key = digestCreator.getDigest();
		key128 = Arrays.copyOfRange(key, 0, 16);
		sec_key_spec = new SecretKeySpec(key128, "AES");
	}

	
	//encryption/decryption function
	private byte[] aes_crypt(byte[] inFile, int mode) throws Exception {
		byte[] converted = null;
		byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		sec_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		try {
			//set cipher to decrypt mode
			if (mode == 1) {
				sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec, ivspec);
			} else if (mode == 2) {
				sec_cipher.init(Cipher.DECRYPT_MODE, sec_key_spec, ivspec);
			}
			//do decryption
			converted = sec_cipher.doFinal(inFile);
		}
		catch (BadPaddingException b)
		{
			sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec, ivspec);
			converted = sec_cipher.doFinal(inFile);
		}
		catch(Exception e){
			System.out.println(e);
		}
		
		return converted;
	}
	
	
	public byte[] getConverted() {
		return converted;
	}
	
}
		