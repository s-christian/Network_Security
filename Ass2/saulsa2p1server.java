import java.security.cert.X509Certificate;
import javax.crypto.Mac;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.nio.ByteBuffer;
import java.io.*;
import java.net.*;

public class saulsa2p1server {
  
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