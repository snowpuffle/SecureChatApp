package server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Scanner;
import javax.crypto.spec.SecretKeySpec;
import security.AuthenticationTool;
import security.ConfidentialityTool;

// Server Class
public class Server {
    private static final int SERVER_PORT = 1234;
    private ServerSocket serverSocket;
    private Socket clientSocket;

    private KeyPair serverKeyPair;
    private PublicKey clientPublicKey;
    private SecretKeySpec secretKey;

    private static Scanner scanner;

    // Default Class Constructor
    public Server() {
        scanner = new Scanner(System.in);
        authenticateUser();
        startServer();
    }

    // Authenticate User
    private static void authenticateUser() {
        System.out.println("** User Authentication **");
        while (true) {
            System.out.print("Enter Server Password: ");
            String password = scanner.nextLine().trim();
            if (AuthenticationTool.authenticate(password, Paths.get("src\\server", "password.txt"))) {
                System.out.println("[SYSTEM] Authenticated!");
                break;
            }
            System.out.println("[SYSTEM] Incorrect Password - Try Again!");
        }
    }

    // Start Server
    private void startServer() {
        try {
            setupConnection();
            setupConfidentiality();
            startClientHandler();
        } catch (IOException e) {
            System.out.println("[SYSTEM] " + e.getMessage());
            shutdown();
        }
    }

    // Create a Server Socket and Accept the Client Connections
    private void setupConnection() throws IOException {
        System.out.println("\n** Establishing Connection **");

        // Create New Server Socket
        serverSocket = new ServerSocket(SERVER_PORT);
        System.out.println("[SYSTEM] Waiting for Client Connection...");

        // Wait and Accept Connection with Client
        clientSocket = serverSocket.accept();
        System.out.println("[SYSTEM] Connected to Client!");
    }

    // Obtain Secret-Shared Key using Diffie-Hellman Algorithm
    private void setupConfidentiality() {
        System.out.println("\n** Generating Shared Key **");

        // Generate Key Pair and Obtain Server's Public Key
        serverKeyPair = ConfidentialityTool.generateKeyPair();
        clientPublicKey = ConfidentialityTool.performKeyExchange(clientSocket, serverKeyPair);

        // Generate Shared Secret Key
        secretKey = ConfidentialityTool.generateSharedSecretKey(clientPublicKey, serverKeyPair);
        if (secretKey != null) {
            System.out.println("[SYSTEM] Successfully Generated Shared Key!");
        }
    }

    // Start a New Thread to Handle the Client Communication
    private void startClientHandler() {
        ClientHandler clientHandler = new ClientHandler(this, clientSocket, secretKey);
        clientHandler.start();
    }

    // Shutdown Server and Resources
    public void shutdown() {
        try {
            if (!serverSocket.isClosed()) {
                serverSocket.close();
            }
            if (!clientSocket.isClosed()) {
                clientSocket.close();
            }
            System.out.println("[SYSTEM] Shutting Down Server.");
        } catch (Exception e) {
            System.out.println("[SYSTEM] Problem with Shutting Down Resources!");
        }
    }

    public static void main(String[] args) {
        // Create and Start New Server
        new Server();
    }
}
