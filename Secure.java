import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;


public class Secure
{

	private static SecretKeySpec sec_key_spec;
	private static Cipher sec_cipher;
	private static Hash digestCreator;
	
	private static byte[] file_buffer;
	private static FileInputStream inFile;
	private static FileOutputStream outFile;
	
	private static final int SHA1_SIZE = 20;

	
	
	public static void keyGenerator(byte[] seed) {
		byte[] key;
		byte[] key128;
	
		//generates key
		digestCreator = new Hash(seed);
		key = digestCreator.getDigest();
		key128 = Arrays.copyOfRange(key, 0, 16);
		sec_key_spec = new SecretKeySpec(key128, "AES");
	}
	
	
	//encryption/decryption function
	public static byte[] aes_crypt(byte[] inFileBuffer, int mode) throws Exception {
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
			converted = sec_cipher.doFinal(inFileBuffer);
		}
		catch (BadPaddingException b)
		{
			sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec, ivspec);
			converted = sec_cipher.doFinal(inFileBuffer);
		}
		catch(Exception e){
			System.out.println(e);
		}
		
		return converted;
	}
	
	
	
	public static int file_intake (String file_name) throws Exception {
		FileInputStream inFile;
		
		String[] inFilename = file_name.split("\\.(?=[^\\.]+$)");
		String outFilename = inFilename[0] + "OUT." + inFilename[1];
		inFile = new FileInputStream(inFilename[0] + "." + inFilename[1]);
		
		//reads message file in buffer
		int file_size = inFile.available();
		file_buffer = new byte[file_size];
		inFile.read(file_buffer);
		inFile.close();
		
		outFile = new FileOutputStream(outFilename);
		
		return file_size;
	}
	
	
	
	public static byte[] combineDigest (byte[] plaintext) {
		byte[] sha1_hash;
		byte[] inBuffer;
		int file_size;
		
		digestCreator.update(file_buffer);
		sha1_hash = digestCreator.getDigest();
		file_size = file_buffer.length;
		
		inBuffer = new byte[file_size + SHA1_SIZE];
		for (int i = 0; i < file_size; i++) {
			inBuffer[i] = file_buffer[i];
		}
		for (int j = 0; j < SHA1_SIZE; j++) {
			inBuffer[file_size + j] = sha1_hash[j];
		}

		return inBuffer;
	}
	
	
	public static byte[] splitDigest (byte[] decrypted) {
		byte[] message;
		byte[] digest;
		byte[] local_digest;
		int file_size;
		
		file_size = decrypted.length;
		message = Arrays.copyOfRange(decrypted, 0, (file_size - SHA1_SIZE));
		digest = Arrays.copyOfRange(decrypted, (file_size - SHA1_SIZE), file_size);
		digestCreator.update(message);
		local_digest = digestCreator.getDigest();
		System.out.println(digestCreator.compareDigests(digest, local_digest));
		
		return message;
	}
	
	public static void main (String args[]) throws Exception 
	{	
		byte[] seed;
		byte[] inBuffer;
		byte[] outBuffer;
		byte[] decrypted;
		String file_name;
		int mode;
		
		try {
			file_name = args[0];
			seed = args[1].getBytes("us-ascii");
			mode = Integer.parseInt(args[2]);
			
			if ((mode != 1) && (mode != 2)) {
				return;
			}
			
			file_intake(file_name);
			
			keyGenerator(seed);
			
			if (mode == 1) {
				inBuffer = combineDigest(file_buffer);
				outBuffer = aes_crypt(inBuffer, mode);
			} else {
				decrypted = aes_crypt(file_buffer, mode);
				outBuffer = splitDigest(decrypted);
			}
			
			outFile.write(outBuffer);
			outFile.close();
		
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	
}
			
			
			
			
		
		