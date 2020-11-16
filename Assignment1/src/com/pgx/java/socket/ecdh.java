package com.pgx.java.socket;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.util.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.io.Console;


public class ecdh {
	
	   private static PrivateKey privateKey;
	    private PublicKey publicKey;
	    private static final String ALGO = "AES";
	    public ecdh() throws NoSuchAlgorithmException {
	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	        keyGen.initialize(1024);
	        KeyPair pair = keyGen.generateKeyPair();
	        this.privateKey = pair.getPrivate();
	        this.publicKey = pair.getPublic();
	    }

	    public void writeToFile(String path, byte[] key) throws IOException {
	        File f = new File(path);
	        f.getParentFile().mkdirs();

	        FileOutputStream fos = new FileOutputStream(f);
	        fos.write(key);
	        fos.flush();
	        fos.close();
	    }

	    public static PrivateKey getPrivateKey() {
	        return privateKey;
	    }
	    public static byte[] encrypt(byte[] Data) throws Exception {
	        Key key = getPrivateKey();
	        Cipher c = Cipher.getInstance(ALGO);
	        c.init(Cipher.ENCRYPT_MODE, key);
	        byte[] encVal = c.doFinal(Data);
	        //String encryptedValue = new BASE64Encoder().encode(encVal);
	        return encVal;
	    }

	    public static byte[] decrypt(byte[] encryptedData) throws Exception {
	        Key key = getPrivateKey();
	        Cipher c = Cipher.getInstance(ALGO);
	        c.init(Cipher.DECRYPT_MODE, key);

	        byte[] decValue = c.doFinal(encryptedData);
	        return decValue;
	    }

	    public PublicKey getPublicKey() {
	        return publicKey;
	    }
	
	
	   public static byte hexToByte(String hexString) {
	        int firstDigit = toDigit(hexString.charAt(0));
	        int secondDigit = toDigit(hexString.charAt(1));
	        return (byte) ((firstDigit << 4) + secondDigit);
	    }
	    
	    private static int toDigit(char hexChar) {
	        int digit = Character.digit(hexChar, 16);
	        if(digit == -1) {
	            throw new IllegalArgumentException(
	              "Invalid Hexadecimal Character: "+ hexChar);
	        }
	        return digit;
	    }
	    
	    public static String byteToHex(byte num) {
	        char[] hexDigits = new char[2];
	        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
	        hexDigits[1] = Character.forDigit((num & 0xF), 16);
	        return new String(hexDigits);
	    }
	    
	    public static String printHexBinary(byte[] byteArray) {
	        StringBuffer hexStringBuffer = new StringBuffer();
	        for (int i = 0; i < byteArray.length; i++) {
	            hexStringBuffer.append(byteToHex(byteArray[i]));
	        }
	        return hexStringBuffer.toString();
	    }
	    
	    public static byte[] parseHexBinary(String hexString) {
	        if (hexString.length() % 2 == 1) {
	            throw new IllegalArgumentException(
	              "Invalid hexadecimal String supplied.");
	        }
	        
	        byte[] bytes = new byte[hexString.length() / 2];
	        for (int i = 0; i < hexString.length(); i += 2) {
	            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
	        }
	        return bytes;
	    }
  public static void main(String[] args) throws Exception {
    Console console = System.console();
    // Generate ephemeral ECDH keypair
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(256);
    KeyPair kp = kpg.generateKeyPair();
    byte[] ourPk = kp.getPublic().getEncoded();

    // Display our public key
    console.printf("Public Key: %s%n", printHexBinary(ourPk));

    // Read other's public key:
   // byte[] otherPk = parseHexBinary(console.readLine("Other PK: "));
    byte[] otherPk = kp.getPublic().getEncoded();
   console.printf("Other Key: %s%n", printHexBinary(otherPk));
    KeyFactory kf = KeyFactory.getInstance("EC");
    X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
    PublicKey otherPublicKey = kf.generatePublic(pkSpec);

    // Perform key agreement
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    ka.init(kp.getPrivate());
    ka.doPhase(otherPublicKey, true);

    // Read shared secret
    byte[] sharedSecret = ka.generateSecret();
    console.printf("Shared secret: %s%n", printHexBinary(sharedSecret));

    // Derive a key from the shared secret and both public keys
    MessageDigest hash = MessageDigest.getInstance("SHA-256");
    hash.update(sharedSecret);
    // Simple deterministic ordering
    List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(otherPk));
    Collections.sort(keys);
    hash.update(keys.get(0));
    hash.update(keys.get(1));

    byte[] derivedKey = hash.digest();
    console.printf("Final key: %s%n", printHexBinary(derivedKey));
    ByteBuffer wrapped = ByteBuffer.wrap(sharedSecret); // big-endian by default
    ByteBuffer depparw = ByteBuffer.wrap(derivedKey); // big-endian by default
    int num = wrapped.getShort(); 
    int mun = depparw.getShort();

    ByteBuffer dbuf = ByteBuffer.allocate(derivedKey.length+sharedSecret.length);
    num = num + mun;
    dbuf.putInt(num);
    byte[] bytes = dbuf.array(); 
    
    console.printf("Encryper Secret: %s%n", printHexBinary(bytes));
    
  }
}
