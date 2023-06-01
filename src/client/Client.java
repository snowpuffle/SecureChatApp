package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Scanner;
import javax.crypto.spec.SecretKeySpec;
import security.AuthenticationTool;
import security.ConfidentialityTool;
import security.IntegrityTool;

public class Client {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1234;
    private Socket clientSocket;

    private BufferedReader consoleReader;
    private BufferedReader reader;
    private PrintWriter writer;
    private static Scanner scanner;

    private KeyPair clientKeyPair;
    private PublicKey serverPublicKey;
    private SecretKeySpec secretKey;

    // Default Class Constructor
    public Client() {
        scanner = new Scanner(System.in);
        authenticateUser();
        startClient();
    }

    // Authenticate User
    private static void authenticateUser() {
        System.out.println("** User Authentication **");
        while (true) {
            System.out.print("Enter Client Password: ");
            String password = scanner.nextLine().trim();
            if (AuthenticationTool.authenticate(password, Paths.get("src\\client", "password.txt"))) {
                System.out.println("[SYSTEM] Authenticated!");
                break;
            }
            System.out.println("[SYSTEM] Incorrect Password - Try Again!");
        }
    }

    // Start Client
    public void startClient() {
        try {
            setupConnection();
            setupConfidentiality();
            communicate();
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("[SYSTEM] " + e.getMessage());
            shutdown();
        }
    }

    // Setup Connection and Initialize Input/Output Streams
    private void setupConnection() throws IOException {
        System.out.println("\n** Establishing Connection **");

        // Create New Client Socket and Connect to Server
        clientSocket = new Socket(SERVER_HOST, SERVER_PORT);
        System.out.println("[SYSTEM] Connected to Server!");

        // Initialize Input/Output Streams for Communication
        reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        writer = new PrintWriter(clientSocket.getOutputStream(), true);
        consoleReader = new BufferedReader(new InputStreamReader(System.in));
    }

    // Obtain Secret Key using Diffie-Hellman Algorithm
    private void setupConfidentiality() {
        System.out.println("\n** Generating Shared Key **");

        // Generate Key Pair and Obtain Server's Public Key
        clientKeyPair = ConfidentialityTool.generateKeyPair();
        serverPublicKey = ConfidentialityTool.performKeyExchange(clientSocket, clientKeyPair);

        // Generate Shared Secret Key
        secretKey = ConfidentialityTool.generateSharedSecretKey(serverPublicKey, clientKeyPair);
        if (secretKey != null) {
            System.out.println("[SYSTEM] Successfully Generated Shared Key!");
        }
    }

    // Handle Communication with Server
    private void communicate() throws IOException {
        System.out.println("\n** Start Chatting! **");

        // Start Communication with Server
        boolean connected = true;
        while (connected) {
            connected = send();
            if (connected) {
                connected = receive();
            }
        }
        shutdown();
    }

    // Handle Receiving Messages from Server
    private boolean receive() throws IOException {
        if (reader == null || reader.ready()) {
            return false;
        }

        // Receive Message from Server
        String serverMessage = reader.readLine();

        // If Null message is Received
        if (serverMessage == null) {
            System.out.println("\n[SYSTEM] Server Has Left the Chat!");
            return false;
        }

        // Split the message into the encrypted message and hash
        String[] parts = serverMessage.split("\\|");
        if (parts.length != 2) {
            System.out.println("\n[SYSTEM] Invalid Message Format!");
            return false;
        }

        // Split and Decrypt the Message
        String encryptedMessage = parts[0];
        String receivedHash = parts[1];
        String decryptedMessage = decryptMessage(encryptedMessage);

        return verifyAndDisplayMessage(decryptedMessage, receivedHash);
    }

    // Handle Sending Messages to Client
    private boolean send() throws IOException {
        // Prompt and Get Message
        System.out.print(">> CLIENT: ");
        String clientMessage = consoleReader.readLine();

        // Disconnect if Client Quits
        if (clientMessage.equalsIgnoreCase("QUIT")) {
            System.out.println("\n[SYSTEM] Disconnected!");
            return false;
        }

        // Attempt to Encrypt and Send Message to Server
        try {
            // Encrypt and Compute Hash of the Original Message
            String encryptedMessage = encryptMessage(clientMessage);
            String hash = computeHash(clientMessage);

            // Send the Encrypted Message + Hash to Server
            sendToServer(encryptedMessage, hash);
        } catch (Exception e) {
            System.out.println("[SYSTEM] " + e.getMessage());
            return false;
        }
        return true;
    }

    // Encrypt the Original Message
    private String encryptMessage(String message) throws Exception {
        return ConfidentialityTool.encrypt(message, secretKey);
    }

    // Decrypt the Encrypted Message
    private String decryptMessage(String message) {
        return ConfidentialityTool.decrypt(message, secretKey);
    }

    // Compute the Hash of the Original Message
    private String computeHash(String message) {
        return IntegrityTool.computeHash(message);
    }

    // Send the Encrypted Message + Hash to Client
    private void sendToServer(String encryptedMessage, String hash) {
        writer.println(encryptedMessage + "|" + hash);
    }

    // Verify the Message Integrity and Display if Valid
    private boolean verifyAndDisplayMessage(String decryptedMessage, String receivedHash) {
        // Verify the Message and Display if Valid
        if (IntegrityTool.verifyIntegrity(decryptedMessage, receivedHash)) {
            // Display Server Message to Output
            System.out.println(">> SERVER: " + decryptedMessage);
            return true;
        } else {
            System.out.println("\n[SYSTEM] Integrity Check Failed!");
            return false;
        }
    }

    // Shutdown Client and Resources
    private void shutdown() {
        try {
            System.out.println("[SYSTEM] Shutting Down Client.");
            if (!clientSocket.isClosed()) {
                clientSocket.close();
            }
            if (reader != null) {
                reader.close();
            }
            if (writer != null) {
                writer.close();
            }
        } catch (Exception e) {
            System.out.println("[SYSTEM] Problem with Shutting Down Resources!");
        }
    }

    public static void main(String[] args) {
        new Client();
    }
}
