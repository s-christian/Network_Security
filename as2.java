import java.security.cert.X509Certificate;
import java.security.*;
import javax.crypto.*;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;
import javax.crypto.KeyAgreement;
import java.util.*;
import java.nio.ByteBuffer;
import java.io.*;
import java.net.*;


//HMAC does not require any crypto function, can sign the message with just the message and agreed key 
//receiver gets message, uses the hash and agreed key to verify the Tag is the same as the received tag 
//Tag is appended to end of message. 
//X509 requires a public key and private key. The sender and reciever generates a public and private key pair, exchange public keys
//sender sends the message, encrypted with receivers public key and signed with senders private key 
//signing the message involves 
//receiver verifies the message came from the intended sender, with senders public key and decrypts message with private key 
 
public class as2 {
  
  
  public static void main(String[] args)throws Exception {
      
            CertAndKeyGen keyGen=new CertAndKeyGen("RSA","SHA256WithRSA");
            keyGen.generate(1024);
             
            //Generate self signed certificate
            X509Certificate[] chain=new X509Certificate[1];
            chain[0]=keyGen.getSelfCertificate(new X500Name("CN=ROOT"), (long)365*3600*24); //the 2nd parameter indicates \
                                                                                            //the time the signature is valid for in seconds
            
            System.out.println("\nCertificate : " + chain[0].toString());
           
            byte[] hash = hmac_sha256("secret", chain[0].toString());
            System.out.printf("HMAC, m: \n" + byteToHex(hash));
           
           
            
            
            String cert = chain[0].toString();
              
            ServerSocket welcomeSocket = new ServerSocket(6655);
 
             while(true) {
      
               Socket connectionSocket = welcomeSocket.accept();
       
               OutputStream outputStream = connectionSocket.getOutputStream();
               DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
          
               dataOutputStream.writeUTF(chain[0].toString());
               dataOutputStream.writeUTF(byteToHex(hash));
               dataOutputStream.flush(); // send the message
               dataOutputStream.close(); // close the ou
               
             }
                
           
         
           
           
    }
  public static byte[] hmac_sha256(String secretKey, String data) throws Exception { //function for computing hmac
    Mac mac = Mac.getInstance("HmacSHA256");
    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
    mac.init(secretKeySpec);
    byte[] digest = mac.doFinal(data.getBytes());
    return digest;
   
  }
  
  public static String byteToHex(byte[] num) { //Function for converting data type of byte to string 
   char[] hexDigits = new char[num.length*2];
   for(int i = 0; i < num.length; i++){ 
    hexDigits[i*2] = Character.forDigit((num[i] >> 4) & 0xF, 16); //num
    hexDigits[(i*2)+1] = Character.forDigit((num[i] & 0xF), 16);
    
   }return new String(hexDigits);  
}
    
    
    
    
    
    
}