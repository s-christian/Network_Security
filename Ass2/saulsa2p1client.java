import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import java.nio.ByteBuffer;
import java.io.*;
import java.net.*;
 
 
public class saulsa2p1client {
  
  public static void main(String[] args)throws Exception {
       
               Socket clientSocket = new Socket("localhost", 6655);

               InputStream inputStream = clientSocket.getInputStream();
               DataInputStream dataInputStream = new DataInputStream(inputStream);

               String strSrvCert = dataInputStream.readUTF();
               String servHmac = dataInputStream.readUTF();
       
               System.out.println("\nCertificate received: " + strSrvCert);
            
               byte[] hmac = hmac_sha256("secret", strSrvCert);
               
               System.out.printf("HMAC from server, m: \n" + servHmac);
               System.out.printf("\nComputed HMAC from message recieved, mc: \n" + byteToHex(hmac));
               
               int difference = byteToHex(hmac).compareTo(servHmac);
               if(difference == 0){
                 System.out.printf("\nThe HMAC from server and computed MHAC match \n");      //comparing hmac received from server and computed hmac 
               }
               else {
                 System.out.printf("\nThe HMAC from server and computed MHAC do not match! The message has been tampered with \n");
               }  
              
    }
  
  public static byte[] hmac_sha256(String secretKey, String data) throws Exception {  //function for computing hmac
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