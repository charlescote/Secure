import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;


public class Secure
{

	private static Hash digestCreator;
	
	private static byte[] file_data;
	private static FileInputStream inFile;
	private static FileOutputStream outFile;
	
	private static final int SHA1_SIZE = 20;
	
	
	
	
	public static void file_handler (String file_name) throws Exception {
		FileInputStream inFile;
		
		String[] inFilename = file_name.split("\\.(?=[^\\.]+$)");
		String outFilename = inFilename[0] + "OUT." + inFilename[1];
		inFile = new FileInputStream(inFilename[0] + "." + inFilename[1]);
		
		//reads message file in buffer
		int file_size = inFile.available();
		file_data = new byte[file_size];
		inFile.read(file_data);
		inFile.close();
		
		outFile = new FileOutputStream(outFilename);
	}
	
	
	
	public static byte[] combineDigest (byte[] plaintext) {
		byte[] sha1_hash;
		byte[] inBuffer;
		int file_size;
		
		digestCreator = new Hash(file_data);
		sha1_hash = digestCreator.getDigest();
		file_size = file_data.length;
		inBuffer = new byte[file_size + SHA1_SIZE];
		for (int i = 0; i < file_size; i++) {
			inBuffer[i] = file_data[i];
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
		digestCreator = new Hash(message);
		local_digest = digestCreator.getDigest();
		System.out.println(digestCreator.compareDigests(digest, local_digest));
		
		return message;
	}
	
	public static void main (String args[]) throws Exception 
	{	
		Crypt crypt;
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
			
			file_handler(file_name);
			
			if (mode == 1) {
				inBuffer = combineDigest(file_data);
				crypt = new Crypt(inBuffer, seed, mode);
				outBuffer = crypt.getConverted();
			} else {
				crypt = new Crypt(file_data, seed, mode);
				decrypted = crypt.getConverted();
				outBuffer = splitDigest(decrypted);
			}
			
			outFile.write(outBuffer);
			outFile.close();
		
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	
}
			
			
			
			
		
		