import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Hash
{

	private static final int SHA1_SIZE = 20;

	private byte[] digest;

	public Hash (byte[] data) {
		try {
			digest = createDigest(data);
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	
	public Hash () {
	
	}
	
	
	public byte[] getDigest() {
		return digest;
	}
	
	
	public void update(byte[] data)
	{
		try {
			digest = createDigest(data);
		} catch (Exception e) {
			System.out.println(e);
		}
		
	}
	
	
	//creates SHA-1 message digest
	private static byte[] createDigest(byte[] message) throws Exception
	{
		byte[] hash = null;
		try{
			//create message digest object
			MessageDigest sha1 = MessageDigest.getInstance("SHA1");
			
			//make message digest
			hash = sha1.digest(message);	
		}
		catch(NoSuchAlgorithmException nsae) {
			System.out.println(nsae);
		}
		return hash;
	}
	
	
	//compares two digests
	public static String compareDigests(byte[] digest, byte[] local_digest)
	{
		for (int i = 0; i < SHA1_SIZE; i++)
		{
			if (digest[i] != local_digest[i]) {
				return "Digests don't match; your file may have been tampered with.";
			}
		}
		return "Digests match!";
	}
	
}