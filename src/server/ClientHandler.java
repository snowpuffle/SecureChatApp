package server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import javax.crypto.spec.SecretKeySpec;
import security.ConfidentialityTool;
import security.IntegrityTool;

public class ClientHandler extends Thread {
    private Socket clientSocket;
    private Server server;

    private BufferedReader consoleReader;
    private BufferedReader reader;
    private PrintWriter writer;

    private SecretKeySpec secretKey;

    // Default Class Constructor
    public ClientHandler(Server server, Socket clientSocket, SecretKeySpec secretKey) {
        this.server = server;
        this.clientSocket = clientSocket;
        this.secretKey = secretKey;
    }

    @Override
    public void run() {
        try {
            initialize();
            communicate();
        } catch (IOException e) {
            System.out.println("[SYSTEM] " + e.getMessage());
            shutdown();
        }
    }

    // Initialize Input/Output Streams for Communication
    private void initialize() throws IOException {
        reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        writer = new PrintWriter(clientSocket.getOutputStream(), true);
        consoleReader = new BufferedReader(new InputStreamReader(System.in));
    }

    // Handle Communication with Client
    private void communicate() throws IOException {
        System.out.println("\n** Start Chatting! **");

        // Start Communication with Client
        boolean connected = true;
        while (connected) {
            connected = receive();
            if (connected) {
                connected = send();
            }
        }
        shutdown();
    }

    // Handle Receiving Messages from Client
    private boolean receive() throws IOException {
        // Receive Message from Client
        String clientMessage = reader.readLine();

        // If Null Message is Received
        if (clientMessage == null) {
            System.out.println("\n[SYSTEM] Client Has Left the Chat!");
            return false;
        }

        // Split the message into the encrypted message and hash
        String[] parts = clientMessage.split("\\|");
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
        System.out.print(">> SERVER: ");
        String serverMessage = consoleReader.readLine();

        // Disconnect if Server Quits
        if (serverMessage.equalsIgnoreCase("QUIT")) {
            System.out.println("\n[SYSTEM] Disconnected!");
            return false;
        }

        // Attempt to Encrypt and Send Message to Client
        try {
            // Encrypt and Compute Hash of the Original Message
            String encryptedMessage = encryptMessage(serverMessage);
            String hash = computeHash(serverMessage);

            // Send the Encrypted Message + Hash to Client
            sendToClient(encryptedMessage, hash);
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
    private void sendToClient(String encryptedMessage, String hash) {
        writer.println(encryptedMessage + "|" + hash);
    }

    // Verify the Message Integrity and Display if Valid
    private boolean verifyAndDisplayMessage(String decryptedMessage, String receivedHash) {
        // Verify the Message and Display if Valid
        if (IntegrityTool.verifyIntegrity(decryptedMessage, receivedHash)) {
            // Display Client Message to Output
            System.out.println(">> CLIENT: " + decryptedMessage);
            return true;
        } else {
            System.out.println("\n[SYSTEM] Integrity Check Failed!");
            return false;
        }
    }

    // Shutdown Server and Resources
    private void shutdown() {
        try {
            System.out.println("[SYSTEM] Shutting Down Client Handler.");
            if (!clientSocket.isClosed()) {
                clientSocket.close();
            }
            if (reader != null) {
                reader.close();
            }
            if (writer != null) {
                writer.close();
            }
            server.shutdown();
        } catch (Exception e) {
            System.out.println("[SYSTEM] Problem with Shutting Down Resources!");
        }
    }
}
