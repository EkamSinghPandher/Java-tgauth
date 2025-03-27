package org.example;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;
import java.util.TreeMap;
import java.util.stream.Collectors;

// Bouncy Castle imports
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Class for validating Telegram Web App authentication data using Bouncy Castle
 */
public class TgAuth {
    private String botId;
    private String publicKeyHex;

    // Static initializer to register the Bouncy Castle provider once
    static {
        // Add Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Constructor that initializes the bot ID and public key
     *
     * @param botId The ID of your Telegram bot
     * @param publicKeyHex The hex-encoded Ed25519 public key
     */
    public TgAuth(String botId, String publicKeyHex) {
        this.botId = botId;
        this.publicKeyHex = publicKeyHex;
    }

    /**
     * Parses a string encoded as a query string and returns a map.
     * Uses TreeMap to maintain alphabetical order (important for validation).
     *
     * @param initData The query string from Telegram WebApp
     * @return A TreeMap containing the parsed key-value pairs
     */
    public TreeMap<String, String> parseTelegramInitData(String initData) {
        TreeMap<String, String> result = new TreeMap<>();

        if (initData == null || initData.isEmpty()) {
            return result;
        }

        String[] pairs = initData.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            if (idx > 0) {
                String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                result.put(key, value);
            }
        }

        return result;
    }

    /**
     * Creates data-check-string for Ed25519 validation.
     * Data-check-string is constructed as follows:
     * 1. Prepend the bot_id, followed by : and the constant string WebAppData.
     * 2. Add a line feed character ('\n', 0x0A).
     * 3. Append all received fields (except hash and signature), sorted alphabetically, in the format key=<value>.
     * 4. Separate each key-value pair with a line feed character ('\n', 0x0A).
     *
     * This is from the telegram docs: https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
     * @param parsedData The parsed query parameters
     * @return The data check string for signature validation
     */
    public String createDataCheckString(TreeMap<String, String> parsedData) {
        String dataCheckString = botId + ":WebAppData\n";

        dataCheckString += parsedData.entrySet().stream()
                .filter(entry -> !entry.getKey().equals("hash") && !entry.getKey().equals("signature"))
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("\n"));

        return dataCheckString;
    }

    /**
     * Validates the Telegram ED25519 signature against the data string using Bouncy Castle.
     *
     * @param parsedData The parsed query parameters
     * @param dataCheckStr The data check string for validation
     * @return true if the signature is valid, false otherwise
     */
    public boolean validateTelegramSignature(TreeMap<String, String> parsedData, String dataCheckStr) {
        try {
            // Extract the signature parameter
            String signatureB64 = parsedData.get("signature");
            if (signatureB64 == null) {
                throw new IllegalArgumentException("Missing 'signature' parameter");
            }

            // Decode base64url signature
            byte[] signatureBytes = Base64.getUrlDecoder().decode(signatureB64);

            // Convert hex public key to bytes
            byte[] publicKeyBytes = hexToBytes(publicKeyHex);

            // Create Ed25519 public key parameters directly from the raw bytes using bouncy castle
            Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);

            // Create an Ed25519Signer for verification
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(false, publicKey); // false for verification mode

            // Add the message to be verified
            byte[] message = dataCheckStr.getBytes(StandardCharsets.UTF_8);
            signer.update(message, 0, message.length);

            // Verify the signature
            return signer.verifySignature(signatureBytes);

        } catch (Exception e) {
            System.err.println("Validation error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Validates the Telegram WebApp init data
     *
     * @param initData The raw query string from Telegram WebApp
     * @return true if the data is valid, false otherwise
     */
    public boolean validateTgAuth(String initData) {
        try {
            TreeMap<String, String> parsedData = parseTelegramInitData(initData);
            String dataCheckString = createDataCheckString(parsedData);
            return validateTelegramSignature(parsedData, dataCheckString);
        } catch (Exception e) {
            System.err.println("Authentication error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Helper method to convert hex string to byte array
     */
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}