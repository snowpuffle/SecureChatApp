package security;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;

public class AuthenticationTool {
    // Authenticate Password with Path
    public static boolean authenticate(String password, Path path) {
        byte[] hashedPasswordBytes = null;
        byte[] storedPasswordBytes = null;

        try (InputStream inputStream = Files.newInputStream(path)) {
            // Read the Stored Hashed Password from the File
            String storedPasswordString = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            storedPasswordBytes = hexStringToByteArray(storedPasswordString);

            // Hash the Password by Converting it to Bytes and Digesting it
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            hashedPasswordBytes = messageDigest.digest(password.getBytes());

            // Compare the Hashed and Stored Passwords
            return Arrays.equals(hashedPasswordBytes, storedPasswordBytes);

        } catch (Exception e) {
            return false;
        }
    }

    // Convert String to Byte Array
    private static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }
}
