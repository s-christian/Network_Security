package assignment1;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
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
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ECDH_Server {
	
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
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC");
		keygen.initialize(384);
		KeyPair keys = keygen.generateKeyPair(); // NIST P-384 elliptic curve (secp384r1)
		PublicKey pubKey = keys.getPublic();
		PrivateKey privKey = keys.getPrivate();
		
		/*
			pubKey					- "Sun EC public key, 384 bits, public x coord:, public y coord:, parameters: secp384r1 [NIST P-384]"
			pubKey.getAlgorithm()	- "EC"
			pubKey.getFormat()		- "X.509"
			privKey					- only provides an identifier for the object
			privKey.getAlgorithm()	- "EC"
			privKey.getFormat()		- "PKCS#8"
		*/
		
		System.out.println("[!] Server PUBLIC key:\t" + bytesToHex(pubKey.getEncoded()));
		System.out.println("[!] Server PRIVATE key:\t" + bytesToHex(privKey.getEncoded()));
		
		System.out.println("");
		
		// Start our socket and listen for and process incoming connections
		@SuppressWarnings("resource")
		ServerSocket welcomeSocket = new ServerSocket(6789);
		while (true) {
			// Wait for a connection
			Socket connectionSocket = welcomeSocket.accept();
			System.out.println("Connection established...");

			// Send the Client our public key
			DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
			outToClient.write(pubKey.getEncoded());
			
			// Receive the Client's encoded public key
			DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream());
			byte[] clientPublicKeyEncoded = new byte[120];
			inFromClient.read(clientPublicKeyEncoded);
			
			// Recreate the Client's public key
			KeyFactory kf = KeyFactory.getInstance("EC");
			PublicKey clientPublicKey = kf.generatePublic(new X509EncodedKeySpec(clientPublicKeyEncoded));
			
			// Diffie-Hellman key exchange to generate the shared secret
			KeyAgreement ka = KeyAgreement.getInstance("ECDH");
			ka.init(privKey);
			ka.doPhase(clientPublicKey, true);
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
			byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0}; // don't really care about the iv for this program
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
			
			try {
				// Retrieve the Client's encrypted message
				byte[] clientEncryptedMessageBytes = new byte[16];
				inFromClient.read(clientEncryptedMessageBytes);
				System.out.println("[=] Client encrypted message:\t" + bytesToHex(clientEncryptedMessageBytes));
				
				// Decrypt and display the Client's message
				byte[] clientDecryptedMessageBytes = cipher.doFinal(clientEncryptedMessageBytes);
				String clientDecryptedMessage = new String(clientDecryptedMessageBytes);
				System.out.println("[+] Client unencrypted message:\t" + clientDecryptedMessage);
				System.out.println("[+] Done!\n");
			} catch (IOException e) {
				System.out.println("Couldn't receive data from Client!\n");
			}
		}
	}
	
}
