package security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class IntegrityTool {
    private static final String HASH_ALGORITHM = "SHA-256";

    // Verify the Integrity by Computing Computed Hash with Received Hash Value
    public static boolean verifyIntegrity(String message, String receivedHash) {
        String computedHash = computeHash(message);
        return computedHash.equals(receivedHash);
    }

    // Compute Hash of a Message using SHA-256 Algorithm
    public static String computeHash(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));

            StringBuilder hashBuilder = new StringBuilder();
            for (byte hashByte : hashBytes) {
                String hex = Integer.toHexString(0xff & hashByte);
                if (hex.length() == 1) {
                    hashBuilder.append('0');
                }
                hashBuilder.append(hex);
            }
            return hashBuilder.toString();

        } catch (Exception e) {
            return null;
        }
    }
}
