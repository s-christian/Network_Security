package com.pgx.java.socket;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
public class MyServerSocket {
    private ServerSocket server;
    public MyServerSocket(String ipAddress) throws Exception {
        if (ipAddress != null && !ipAddress.isEmpty()) 
          this.server = new ServerSocket(0, 1, InetAddress.getByName(ipAddress));
        else 
          this.server = new ServerSocket(0, 1, InetAddress.getLocalHost());
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
    //Pass the Public Key through this function to send it to the client
	    private void givePK(byte[] ourPK) throws Exception
	    {
	    	String data = null;
	    	Socket client = this.server.accept();
	    	String clientAddress = client.getInetAddress().getHostAddress();
	    	OutputStream output = client.getOutputStream();
	    	System.out.println(ourPK);
	    }
	    //The server is taking in data from client. It simply gets the clients IP ADdress, and whatever message the client sends
    private void listen() throws Exception {
        String data = null;
        Socket client = this.server.accept();
        String clientAddress = client.getInetAddress().getHostAddress();
        System.out.println("\r\nNew connection from " + clientAddress);
        
        BufferedReader in = new BufferedReader(
                new InputStreamReader(client.getInputStream()));        
        while ( (data = in.readLine()) != null ) {
            System.out.println("\r\nMessage from " + clientAddress + ": " + data);
        }
    }
    public InetAddress getSocketAddress() {
        return this.server.getInetAddress();
    }
    
    public int getPort() {
        return this.server.getLocalPort();
    }
    public static void main(String[] args) throws Exception {
    	  // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        byte[] ourPk = kp.getPublic().getEncoded();
       
    	//When running program, be sure to put ipAddress in command line, else change args[0] to your ipAddress
    	MyServerSocket app = new MyServerSocket("192.168.0.10");
        System.out.println("\r\nRunning Server: " + 
                "Host=" + app.getSocketAddress().getHostAddress() + 
                " Port=" + app.getPort());
       app.givePK(ourPk);
        app.listen();
    }
}
