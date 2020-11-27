package assignment1;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ECDH_Client {
	
	// https://www.baeldung.com/java-random-string
	public static String getRandomString() {
		// Random String will include all ASCII letters, numbers, and symbols
		int leftBound = 33; // "!"
		int rightBound = 126; // "~"
		int strLen = 10;
		
		Random random = new Random();
		
		String randomString = random.ints(leftBound, rightBound + 1)
				.limit(strLen)
				.collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
				.toString();
		
		return randomString;
	}
	
	// https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
	private static String bytesToHex(byte[] bytes) {
		final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
	    for (int i = 0; i < bytes.length; i++) {
	        int bits = bytes[i] & 0xFF; // "& 0xFF": match last 8 bits, gets rid of negative numbers due to int casting
	        hexChars[i * 2] = HEX_ARRAY[bits >>> 4];
	        hexChars[i * 2 + 1] = HEX_ARRAY[bits & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	// I know; that's a lot of thrown exceptions.
	public static void main(String[] args) throws UnknownHostException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		// Generate random String
		String randomString = getRandomString();
		System.out.println("[=] Unencrypted message:\t" + randomString);
		
		// Generate NIST P-384 (secp384r1) Elliptic Curve key pair
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC");
		keygen.initialize(384);
		KeyPair keys = keygen.generateKeyPair(); // NIST P-384 elliptic curve (secp384r1)
		PublicKey pubKey = keys.getPublic();
		PrivateKey privKey = keys.getPrivate();
		byte[] pubKeyEncoded = pubKey.getEncoded();
		byte[] privKeyEncoded = privKey.getEncoded();
		
		// Display Client keys in hex format
		System.out.println("[!] Client PUBLIC key:\t" + bytesToHex(pubKeyEncoded));
		System.out.println("[!] Client PRIVATE key:\t" + bytesToHex(privKeyEncoded));
		
		// Create the Socket to communicate with the Server
		Socket clientSocket = new Socket("localhost", 6789);
		
		// Send the Server our public key
		DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
		outToServer.write(pubKeyEncoded);
		
		// Receive the Server's encoded public key
		DataInputStream inFromServer = new DataInputStream(clientSocket.getInputStream());
		byte[] serverPublicKeyEncoded = new byte[120];
		inFromServer.read(serverPublicKeyEncoded);
		
		// Recreate the Server's public key
		KeyFactory kf = KeyFactory.getInstance("EC");
		PublicKey serverPublicKey = kf.generatePublic(new X509EncodedKeySpec(serverPublicKeyEncoded));
		
		// Diffie-Hellman key exchange to generate the shared secret
		KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		ka.init(privKey);
		ka.doPhase(serverPublicKey, true);
		byte[] sharedSecret = ka.generateSecret();
		System.out.println("[?] Shared secret:\t" + bytesToHex(sharedSecret));
		
		// Hash the secret for obfuscation of what our key is
		MessageDigest secretHasher = MessageDigest.getInstance("SHA-256");
		secretHasher.update(sharedSecret);
		byte[] secretHash = secretHasher.digest();
		
		// Create the final secret key
		SecretKey secretKey = new SecretKeySpec(secretHash, 0, secretHash.length, "AES");
		System.out.println("[?] Final secret key:\t" + bytesToHex(secretKey.getEncoded())); // same as our secretHash, now just in a friendlier form
		
		// Prepare our encryption format with our secret key
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // don't really care about the iv for this program
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
		
		// Encrypt our message
		byte[] randomStringBytes = randomString.getBytes();
		byte[] cipherText = cipher.doFinal(randomStringBytes);
		System.out.println("[=] Encrypted message:\t\t" + bytesToHex(cipherText));
		
		// Send our encrypted message to the Server
		outToServer.write(cipherText);
		clientSocket.close();
		
		System.out.println("[+] Sent and done!");
	}
	
}
