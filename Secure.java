import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;


public class Secure
{

	private static SecretKeySpec sec_key_spec;
	private static Cipher sec_cipher;
	private static final int SHA1_SIZE = 20;

	
	
	// encryption function
	public static byte[] encrypt(byte[] plaintext) throws Exception
	{
		byte[] encrypted = null;
		byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		try {
			//set cipher object to encrypt mode
			sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec, ivspec);

			//create ciphertext
			encrypted = sec_cipher.doFinal(plaintext);
		}
		catch(Exception e) {
			System.out.println(e);
		}
		return encrypted;
	}
	
	
	//decryption function
	public static byte[] decrypt(byte[] ciphertext) throws Exception{
		byte[] decrypted = null;
		byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		try{
			//set cipher to decrypt mode
			sec_cipher.init(Cipher.DECRYPT_MODE, sec_key_spec, ivspec);

			//do decryption
			decrypted = sec_cipher.doFinal(ciphertext);
		}
		catch (BadPaddingException b)
		{
			sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec, ivspec);
			decrypted = sec_cipher.doFinal(ciphertext);
		}
		catch(Exception e){
			System.out.println(e);
		}
		
		return decrypted;
	}

	
	
	public static void main (String args[]) throws Exception 
	{	
		byte[] key;
		byte[] key128;
		FileInputStream inFile;
		FileOutputStream outFile;
		byte[] inBuffer;
		byte[] outBuffer;
		byte[] digest;
		byte[] local_digest;
		byte[] sha1_hash;	
		byte[] buffer;
		byte[] message;
		byte[] decrypted;
		Hash digestCreator;
		String outFilename;
		int file_size;
		
		try {
			if (!(args[2].equals("1")) && !(args[2].equals("2"))) {
				return;
			}
			
			//gets filenames and fileinput
			String[] inFilename = args[0].split("\\.(?=[^\\.]+$)");
			outFilename = inFilename[0] + "OUT." + inFilename[1];
			inFile = new FileInputStream(inFilename[0] + "." + inFilename[1]);
			
			//reads message file in buffer
			file_size = inFile.available();
			buffer = new byte[file_size];
			inFile.read(buffer);
			inFile.close();
			
			//generates key
			digestCreator = new Hash(args[1].getBytes("us-ascii"));
			key = digestCreator.getDigest();
			key128 = Arrays.copyOfRange(key, 0, 16);
			sec_key_spec = new SecretKeySpec(key128, "AES");
			sec_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			if (args[2].equals("1")) {
				//creates sha1 digest from message
				digestCreator.update(buffer);
				sha1_hash = digestCreator.getDigest();
				
				inBuffer = new byte[file_size + SHA1_SIZE];
				for (int i = 0; i < file_size; i++) {
					inBuffer[i] = buffer[i];
				}
				for (int j = 0; j < SHA1_SIZE; j++) {
					inBuffer[file_size + j] = sha1_hash[j];
				}
				
				outBuffer = encrypt(inBuffer);
				
			} else {
				decrypted = decrypt(buffer);
				file_size = decrypted.length;
				message = Arrays.copyOfRange(decrypted, 0, (file_size - SHA1_SIZE));
				digest = Arrays.copyOfRange(decrypted, (file_size - SHA1_SIZE), file_size);
				digestCreator.update(message);
				local_digest = digestCreator.getDigest();
				System.out.println(digestCreator.compareDigests(digest, local_digest));
				outBuffer = message;
			}
			
			outFile = new FileOutputStream(outFilename);
			outFile.write(outBuffer);
			outFile.close();
		
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	
}
			
			
			
			
		
		