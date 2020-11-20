import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;

import java.util.*;
import java.nio.ByteBuffer;




import java.io.*;
import java.net.*;

class Stest {
  public static int size;

  public static void main(String argv[]) throws Exception
    {
    
    
    String key;
    
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(256);
    KeyPair kp = kpg.generateKeyPair();
    byte[] ourPk = kp.getPublic().getEncoded();
    
    size = ourPk.length; 
    
    KeyPairGenerator akpg = KeyPairGenerator.getInstance("EC");
    akpg.initialize(256);
    KeyPair akp = akpg.generateKeyPair();
    byte[] otherPk = akp.getPublic().getEncoded();
   
    
    
    System.out.println("Server key in Hex: \n" + byteToHex(ourPk));
    
    

    ServerSocket welcomeSocket = new ServerSocket(6777);
 
    while(true) {
 
           Socket connectionSocket = welcomeSocket.accept();

           BufferedReader inFromClient =
             new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

           DataOutputStream  outToClient =
             new DataOutputStream(connectionSocket.getOutputStream());
           
     
           
           key = inFromClient.readLine(); //client key read is as Hex string 
           System.out.println("\nClient Public Key hex:  \n" + key);
           
           outToClient.writeBytes(byteToHex(ourPk) + '\n');
          
           
           outToClient.close();
          
           for(int i = 0; i < size; i++){  //client key in string is read into otherPk as data type byte 
             otherPk[i] = hexToByte(key,i);
           }
     
        
          
           
           KeyFactory kf = KeyFactory.getInstance("EC");
           X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
           PublicKey otherPublicKey = kf.generatePublic(pkSpec);

           // Perform key agreement
           KeyAgreement ka = KeyAgreement.getInstance("ECDH");
           ka.init(kp.getPrivate());
           ka.doPhase(otherPublicKey, true);

           // Read shared secret
           byte[] sharedSecret = ka.generateSecret();
           System.out.printf("\n\nShared secret: %s%n", byteToHex(sharedSecret));

           // Derive a key from the shared secret and both public keys
           MessageDigest hash = MessageDigest.getInstance("SHA-256");
           hash.update(sharedSecret);
           // Simple deterministic ordering
           List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(otherPk), ByteBuffer.wrap(ourPk));
           Collections.sort(keys);
           hash.update(keys.get(0));
           hash.update(keys.get(1));

           byte[] derivedKey = hash.digest();
           System.out.printf("Final key: %s%n", byteToHex(derivedKey));
        
           
           
           
        }
    }
  
  public static byte hexToByte(String hexString, int i) {
    int firstDigit = toDigit(hexString.charAt(i*2));
    int secondDigit = toDigit(hexString.charAt(i*2+1));
    return (byte) ((firstDigit << 4) + secondDigit);
    }
    

  
   public static String byteToHex(byte[] num) { //does the converting
   char[] hexDigits = new char[num.length*2];
   for(int i = 0; i < num.length; i++){ 
    hexDigits[i*2] = Character.forDigit((num[i] >> 4) & 0xF, 16); //num
    hexDigits[(i*2)+1] = Character.forDigit((num[i] & 0xF), 16);
    
   }return new String(hexDigits);  
}
   
   
   public static int toDigit(char hexChar) {
    int digit = Character.digit(hexChar, 16);
    if(digit == -1) {
        throw new IllegalArgumentException(
          "Invalid Hexadecimal Character: "+ hexChar);
    }
    return digit;
}
  
  
  
}
  
  
 