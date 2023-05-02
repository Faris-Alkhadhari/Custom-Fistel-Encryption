import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class decrypt {

	public static void main(String[] args) {
	
	
		//Check if terminal inputs have valid number of arguments
		inputValidation(args);
		
		//get files name
		String inputFileName = args[1];
		String outputFileName = args[2]; 
		
		byte[] key = getKey(args[0]);
		System.out.println("This is the input key:: "+convertByteToHexString(key));
		
		//Generate the rounds keys with the help of MD5 hashing
		byte[] key1 = keysGenerator(key);
		byte[] key2 = keysGenerator(key1);
		System.out.println("This is the key1:: "+convertByteToHexString(key1));
		System.out.println("This is the key2:: "+convertByteToHexString(key2));
		
		decryption(inputFileName,outputFileName, key1, key2);
		
	}
	
	private static String convertByteToHexString(byte[] block16) {
		String hexb="";
		for (byte b : block16) {
			hexb += String.format("%02x", b);
		}
		
		return hexb;
	}
	private static void inputValidation(String[] args) {
		
		if(args.length != 3) {
			 System.err.println("WRONG inputs,"
			 		+ "\nPlease input in the following format "
			 		+ "\"java test key inputfile outputfile\"");
			 System.exit(1);
		}
	}
	
	public static byte[] getKey(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	private static byte[] keysGenerator(byte[] key) {
		byte[] roundKey= new byte[4];
		
		byte[] hash = getKeyHash(key);
		
		for(int i=0; i<4 ;i++) {
			roundKey[i] = hash[i];
		}
		
		return roundKey;
	}
	
	private static void decryption(String inputFileName, String outputFileName,byte[] key1, byte[] key2 ) {
		try
		(
				//"Opening files" Making a file i/o stream to read/write to the files
				FileInputStream openInputFile = new FileInputStream(inputFileName);
				FileOutputStream openOutputFile = new FileOutputStream(outputFileName);
				
				//finally let the block mode of i/o files be assigned to java readers/writers
				InputStream input = openInputFile;
				OutputStream output = openOutputFile;
		)
		{
			//8*4 = 32 bits 
			byte[] block = new byte[4];
			
			/*how read(byte array) works:
			 * 
			 * check the next 4 bytes, 
			 * and store them in block array.
			 * 
			 * if all 4 bytes are null in the file
			 * return -1
			 * */
			
			int counter = 0;
			
			while(input.read(block) != -1) {
				
				
				block = fistel(block, key1, key2);
				
				output.write(block);
				
				counter++;
			}
			System.out.println("Blocks number: "+counter+"\n");
			
			System.out.println("Done Copying...");
		}catch(IOException e) {
			e.printStackTrace();
		}
	}
	

	private static byte[] fistel(byte[] plainBlock, byte[] key1, byte[] key2) {
		byte[] cipherBlock =new byte[4];
		byte[] round = new byte[4];
		byte[] left = new byte[2];
		byte[] right= new byte[2];
		
		//round 1
		left[0] = plainBlock[0];
		left[1]= plainBlock[1];
		right[0]= plainBlock[2];
		right[1]= plainBlock[3];

		round = round(left, right,key2);
		
		//round 2
		left[0] = round[0];
		left[1]= round[1];
		right[0]= round[2];
		right[1]= round[3];
		
		round = round(left, right,key1);
		
		//swap left with right
		cipherBlock[0] = round[2];
		cipherBlock[1] = round[3];
		cipherBlock[2] = round[0];
		cipherBlock[3] = round[1];
		
		return cipherBlock;
	}
	
	private static byte[] getKeyHash(byte[] key) {
		MessageDigest md;
		byte[] theMD5digest = null;
		
		try {
			md = MessageDigest.getInstance("MD5");
			md.update(key);  
			theMD5digest = md.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		//System.out.println("Key Hashed");
		return theMD5digest;
	}
	
	private static byte[] round(byte[] left, byte[] right, byte[] key) {
		byte[] roundBlock = new byte[4];// 0 1 2 3
		
		roundBlock[0] = right[0];
		roundBlock[1] = right[1];
		
		byte[] functionOutput = function(right, key);
		
		roundBlock[2] = (byte) (left[0] ^ functionOutput[0]);
		roundBlock[3] = (byte) (left[1] ^ functionOutput[1]);
		
		return roundBlock;
	}
	private static byte[] function(byte[] right, byte[] key) {
		byte[] functionOutput = new byte[2];
		
		
		//P-box 16-16
		byte[] PBoxOutput = getPBoxByte(right);
		
		//xor 32-32 (16-16 for now)
		PBoxOutput[0] = (byte) (PBoxOutput[0] ^ key[0]);
		PBoxOutput[1] = (byte) (PBoxOutput[1] ^ key[1]);
		
		//P Inverse 16-16
		functionOutput = getPInverseBoxByte(PBoxOutput);
		
		return functionOutput;
	}
	private static byte[] getPBoxByte(byte[] right) {
		byte[] result = new byte[2];
		
		//transform bytes into series of bits in boolean form
		boolean [] block16 = new boolean[16];
		for (int i=0; i<8 ;i++) {
			block16[i] = (right[0] & (byte)(Math.pow(2, i))) !=0;
		}
		for (int i=8; i<16 ;i++) {
			block16[i] = (right[1] & (byte)(Math.pow(2, i))) !=0;
		}
		
		//Permutate the bits 
		boolean [] temp = block16;
		
		block16[0]= temp[2];
		block16[1]= temp[10];
		block16[2]= temp[15];
		block16[3]= temp[3];
		block16[4]= temp[7];
		block16[5]= temp[9];
		block16[6]= temp[1];
		block16[7]= temp[5];
		block16[8]= temp[11];
		block16[9]= temp[14];
		block16[10]= temp[4];
		block16[11]= temp[8];
		block16[12]= temp[12];
		block16[13]= temp[0];
		block16[14]= temp[13];
		block16[15]= temp[6];
		
		//reconstructing the two bytes from the permutated bits series
		int b=0;
		for (int i=0; i<8;i++) {
			if(block16[i]) {
				b+= Math.pow(2, i);
			}
		}
		byte result0 = (byte) b;
		
	    b=0;
		for (int i=8; i<16;i++) {
			if(block16[i]) {
				b+= Math.pow(2, i);
			}
		}
		byte result1 = (byte) b;
		
		//Assigned each byte to the byte array respectively
		result[0] = result0;
		result[1] = result1;
		
		return result;
	}
	
	private static byte[] getPInverseBoxByte(byte[] cipherBlock) {
		byte[] result = new byte[2];
		
		//transform bytes into series of bits in boolean form
		boolean [] block16 = new boolean[16];
		for (int i=0; i<8 ;i++) {
			block16[i] = (cipherBlock[0] & (byte)(Math.pow(2, i))) !=0;
		}
		for (int i=8; i<16 ;i++) {
			block16[i] = (cipherBlock[1] & (byte)(Math.pow(2, i))) !=0;
		}
		
		//Permutate the bits 
		boolean [] temp = block16;
		
		block16[0]= temp[13];
		block16[1]= temp[6];
		block16[2]= temp[0];
		block16[3]= temp[3];
		block16[4]= temp[10];
		block16[5]= temp[7];
		block16[6]= temp[15];
		block16[7]= temp[4];
		block16[8]= temp[11];
		block16[9]= temp[5];
		block16[10]= temp[1];
		block16[11]= temp[8];
		block16[12]= temp[12];
		block16[13]= temp[14];
		block16[14]= temp[9];
		block16[15]= temp[2];
		
		//reconstructing the two bytes from the permutated bits series
		int b=0;
		for (int i=0; i<8;i++) {
			if(block16[i]) {
				b+= Math.pow(2, i);
			}
		}
		byte result0 = (byte) b;
		
	    b=0;
		for (int i=8; i<16;i++) {
			if(block16[i]) {
				b+= Math.pow(2, i);
			}
		}
		byte result1 = (byte) b;
		
		//Assigned each byte to the byte array respectively
		result[0] = result0;
		result[1] = result1;
		
		return result;
	}
	
}
