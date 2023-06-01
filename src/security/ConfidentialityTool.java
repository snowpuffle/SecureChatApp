package security;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ConfidentialityTool {
    private static BigInteger g = new BigInteger("1234567890", 16);
    private static BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
            + "FFFFFFFFFFFFFFFF", 16);
    private static int l = 512;

    // Generate a Key Pair using Diffie-Hellman Algorithm
    public static KeyPair generateKeyPair() {
        try {
            // Create Algorithm Parameters P, G, and L
            AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("DH");
            algorithmParameters.init(new DHParameterSpec(p, g, l));

            // Create and Initialize a KeyPairGenerator with the DH Algorithm
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(algorithmParameters.getParameterSpec(DHParameterSpec.class));
            return keyPairGenerator.generateKeyPair();

        } catch (Exception e) {
            System.out.println("[SYSTEM] Error: " + e.getMessage());
            return null;
        }
    }

    // Handle Key Exchange Process
    public static PublicKey performKeyExchange(Socket socket, KeyPair keyPair) {
        try {
            // Initialize Input/Output Streams
            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());

            // Send and Receive Public Key
            DHPublicKey myPublicKey = (DHPublicKey) keyPair.getPublic();
            outputStream.writeObject(myPublicKey);
            PublicKey yourPublicKey = (PublicKey) inputStream.readObject();
            return yourPublicKey;

        } catch (Exception e) {
            System.out.println("[SYSTEM] Error: " + e.getMessage());
            return null;
        }
    }

    // Generate Shared Secret Key from Public Key
    public static SecretKeySpec generateSharedSecretKey(PublicKey publicKey, KeyPair keyPair) {
        try {
            // Initialize Key Agreement with the Private Key
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());

            // Perform the Key Agreement Phase with the Public Key
            keyAgreement.doPhase(publicKey, true);

            /// Generate the Shared Secret
            byte[] sharedSecret = keyAgreement.generateSecret();

            // Generate a Symmetric Key from the Shared Secret
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] hashedSecret = sha.digest(sharedSecret);
            return new SecretKeySpec(hashedSecret, "AES");

        } catch (Exception e) {
            System.out.println("[SYSTEM] Error: " + e.getMessage());
            return null;
        }
    }

    // Encrypt a Message with Secret Key
    public static String encrypt(String message, SecretKeySpec secretKey) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            System.out.println("[SYSTEM] Error: " + e.getMessage());
            return null;
        }
    }

    // Decrypt a Message with Secret Key
    public static String decrypt(String encryptedMessage, SecretKeySpec secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            System.out.println("[SYSTEM] Error: " + e.getMessage());
            return null;
        }
    }
}
