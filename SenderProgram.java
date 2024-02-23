import java.io.File;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.util.zip.CRC32;
import javax.crypto.Cipher;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;


public class SenderProgram {
    
    public static void main(String[] args) throws Exception {
        // Create file chooser
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
        fileChooser.setFileFilter(new FileNameExtensionFilter("Text files", "txt"));

        // Show the file chooser dialog and get the selected file
        int result = fileChooser.showOpenDialog(null);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File selectedFile = fileChooser.getSelectedFile();

        byte[] publicKeyBytes = Files.readAllBytes(Paths.get("ReceiverPublickey.pem"));
        X509EncodedKeySpec realKey = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey recipientPublicKey = factory.generatePublic(realKey);
        
        transferFileWithPublicKey(selectedFile, recipientPublicKey);
    }
    
    public static void transferFileWithPublicKey(File file, PublicKey publicKey) throws Exception {
        byte[] messageBytes = Files.readAllBytes(file.toPath());

        // Calculate checksum
        CRC32 crc = new CRC32();
        crc.update(messageBytes);
        System.out.println("Checksum = " + crc.getValue());

        // Generate a random key for XOR encryption with the same length as the message
        byte[] key1 = new byte[messageBytes.length];
        new SecureRandom().nextBytes(key1);
        byte[] key2 = new byte[messageBytes.length];
        new SecureRandom().nextBytes(key2);
        byte[] key3 = new byte[messageBytes.length];
        new SecureRandom().nextBytes(key3);

        // Encrypt key2 using RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey2 = cipher.doFinal(key2);
        Files.write(Paths.get("encryptedKey2.dat"), encryptedKey2);

        // Encrypt key3 using RSA
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey3 = cipher.doFinal(key3);
        Files.write(Paths.get("encryptedKey3.dat"), encryptedKey3);

        // XOR key1 with key2
        byte[] encryptedBytesKey = new byte[messageBytes.length];
        for (int i = 0; i < messageBytes.length; i++) {
            encryptedBytesKey[i] = (byte) (key1[i] ^ key2[i]);
        }

        // XOR key1XOR2 with key3
        byte[] encryptedBytesKey2 = new byte[messageBytes.length];
        for (int i = 0; i < messageBytes.length; i++) {
            encryptedBytesKey2[i] = (byte) (encryptedBytesKey[i] ^ key3[i]);
        }

        // Encrypt the modified key1 using RSA
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey1 = cipher.doFinal(encryptedBytesKey2);
        Files.write(Paths.get("encryptedKey1.dat"), encryptedKey1);

        // XOR encrypt the message
        byte[] encryptedBytes = new byte[messageBytes.length];
        for (int i = 0; i < messageBytes.length; i++) {
            encryptedBytes[i] = (byte) (messageBytes[i] ^ key1[i]);
        }

        System.out.println("Is your server on?");
        Scanner scan = new Scanner(System.in);
        String yes = scan.nextLine();

        // Transfer the encrypted file
        //"127.0.0.1" loopback ip address
        //ip address for the receiver computer here
        String ipAddress = "172.20.10.5";
        int portNumber = 8080;

        Socket socket = new Socket(ipAddress, portNumber);
        OutputStream out1 = socket.getOutputStream();
        out1.write(encryptedBytes);
        out1.flush();
        out1.close();

        // Close the socket
        socket.close();
    }
}
