import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.zip.CRC32;
import javax.crypto.Cipher;


public class ReceiverProgram {
    
    public static void main(String[] args) throws Exception {
        // Generate RSA keys
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        // Get public and private keys
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        
         Files.write(Paths.get("ReceiverPublickey.pem"), publicKey.getEncoded());
         
         Scanner scan=new Scanner(System.in);
         System.out.println("Did u get your files? ");
         String yes=scan.nextLine();
        
        // Receive encrypted key from sender
        byte[] encryptedKey1 = Files.readAllBytes(Paths.get("encryptedKey1.dat"));
        byte[] encryptedKey2 = Files.readAllBytes(Paths.get("encryptedKey2.dat"));
        byte[] encryptedKey3 = Files.readAllBytes(Paths.get("encryptedKey3.dat"));

        
        
        // Decrypt key1 using RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] key1 = cipher.doFinal(encryptedKey1);
        
        // Decrypt key2 using RSA
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] key2 = cipher.doFinal(encryptedKey2);
        
        // Decrypt key3 using RSA
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] key3 = cipher.doFinal(encryptedKey3);
        
        
        
      
        int PortNumber=8080;
        

        ServerSocket ServerSide=new ServerSocket(PortNumber);
        Socket ClientSide = ServerSide.accept();
        //secure connection protocol https by port 8080
        System.out.println("client connected successfully");
        
         FileOutputStream outputStream = new FileOutputStream("encryptedMessage.dat");
         InputStream inputstream = ClientSide.getInputStream();
         byte[] BUFFER=new byte[1028];
         int readIndex;
         while((readIndex = inputstream.read(BUFFER)) != -1) {
             outputStream.write(BUFFER, 0, readIndex);
         }
         
         outputStream.close();
         inputstream.close();
         ServerSide.close();
         ClientSide.close();
         
         
        
         byte[] encryptedMessage = Files.readAllBytes(Paths.get("encryptedMessage.dat"));
        
         
         
        // step one ; decrypt key1 with key2
        byte[] decryptedKeyBytes1 = new byte[encryptedMessage.length];
        for (int i = 0; i < encryptedMessage.length; i++) {
            decryptedKeyBytes1[i] = (byte)(key1[i] ^ key2[i]);
        }
        
        
         // step two ; decrypt key1 with key3
        byte[] decryptedKeyBytes2 = new byte[encryptedMessage.length];
        for (int i = 0; i < encryptedMessage.length; i++) {
            decryptedKeyBytes2[i] = (byte)(decryptedKeyBytes1[i] ^ key3[i]);
        }
        

        // Receive encrypted message from sender

        // XOR decrypt the message using the same key
        byte[] decryptedKeyBytes3 = new byte[encryptedMessage.length];
        for (int i = 0; i < encryptedMessage.length; i++) {
            decryptedKeyBytes3[i] = (byte)(encryptedMessage[i] ^ decryptedKeyBytes2[i]);
        }

        // Print out the decrypted message
        System.out.println("Decrypted Message: " + new String(decryptedKeyBytes3));
        CRC32 crc=new CRC32();
        crc.update(decryptedKeyBytes3);
        System.out.println("Chuckssum = "+ crc.getValue());
    }
}
