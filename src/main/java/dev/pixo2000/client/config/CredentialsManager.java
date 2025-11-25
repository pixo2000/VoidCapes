package dev.pixo2000.client.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.pixo2000.Voidcapes;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Stores cape login credentials encrypted on disk so the capeset commands can run unattended.
 */
public final class CredentialsManager {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    private final Path credentialsPath;
    private final Path keyPath;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public CredentialsManager(Path configDir) {
        this.credentialsPath = configDir.resolve("voidcapes_credentials.enc");
        this.keyPath = configDir.resolve("voidcapes_key.dat");
    }

    public void storeCredentials(String username, String password) throws Exception {
        CredentialsData data = new CredentialsData(username, password);
        byte[] payload = gson.toJson(data).getBytes(StandardCharsets.UTF_8);
        SecretKey key = getOrCreateKey();
        byte[] encrypted = encrypt(payload, key);
        Files.createDirectories(credentialsPath.getParent());
        Files.write(credentialsPath, encrypted);
        Voidcapes.LOGGER.info("Stored cape credentials for {}", username);
    }

    public CredentialsData loadCredentials() throws Exception {
        if (!Files.exists(credentialsPath) || !Files.exists(keyPath)) {
            return null;
        }
        byte[] encrypted = Files.readAllBytes(credentialsPath);
        SecretKey key = loadKey();
        byte[] decrypted = decrypt(encrypted, key);
        return gson.fromJson(new String(decrypted, StandardCharsets.UTF_8), CredentialsData.class);
    }

    public boolean hasCredentials() {
        return Files.exists(credentialsPath) && Files.exists(keyPath);
    }

    public void deleteCredentials() throws IOException {
        if (Files.exists(credentialsPath)) {
            Files.delete(credentialsPath);
        }
        if (Files.exists(keyPath)) {
            Files.delete(keyPath);
        }
    }

    private SecretKey getOrCreateKey() throws Exception {
        if (Files.exists(keyPath)) {
            return loadKey();
        }
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256);
        SecretKey key = keyGenerator.generateKey();
        Files.createDirectories(keyPath.getParent());
        Files.write(keyPath, key.getEncoded());
        return key;
    }

    private SecretKey loadKey() throws IOException {
        byte[] keyBytes = Files.readAllBytes(keyPath);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    private byte[] encrypt(byte[] payload, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));
        byte[] encrypted = cipher.doFinal(payload);
        byte[] output = new byte[GCM_IV_LENGTH + encrypted.length];
        System.arraycopy(iv, 0, output, 0, GCM_IV_LENGTH);
        System.arraycopy(encrypted, 0, output, GCM_IV_LENGTH, encrypted.length);
        return output;
    }

    private byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(encryptedData, 0, iv, 0, GCM_IV_LENGTH);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));
        byte[] ciphertext = new byte[encryptedData.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedData, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);
        return cipher.doFinal(ciphertext);
    }

    public static final class CredentialsData {
        private final String username;
        private final String password;
        private final long timestamp;

        public CredentialsData(String username, String password) {
            this.username = username;
            this.password = password;
            this.timestamp = System.currentTimeMillis();
        }

        public String username() {
            return username;
        }

        public String password() {
            return password;
        }

        public long timestamp() {
            return timestamp;
        }
    }
}
