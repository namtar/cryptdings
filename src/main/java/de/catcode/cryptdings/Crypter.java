package de.catcode.cryptdings;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Enthält die entsprechenden kryptografischen Methoden.
 * <p>
 * Für verfügbare AlgorithmParameterNames siehe.
 * <a href="https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html"></a>
 * <p>
 * Passender RFC
 * <a href="https://datatracker.ietf.org/doc/html/rfc8018>RFC8018</a>
 * NIST zum Thema Passwort Wahl
 * <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf"></a>*
 * <p>
 * Beispiele:
 * <a href="https://www.baeldung.com/java-aes-encryption-decryption"></a>
 * <a href="https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption"></a>
 * <a href="http://codeplanet.eu/tutorials/cpp/51-advanced-encryption-standard.html"></a>
 * <a href="https://itsecblog.de/rijndael-aes-sichere-block-und-schluesselgroessen/"></a>
 */
public class Crypter {

    private static final int ITERATIONS = 65536;
    // Schlüssellänger für AES Secret Key. 256bit, wobei die Blocklänge bei AES immer 128bit ist. Nicht verwechseln.
    private static final int KEY_LENGTH = 256;

    public SecretKey deriveFromPassword(final String password, final String salt) {

        try {
            final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            final KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), ITERATIONS, KEY_LENGTH);
            final SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
            return new SecretKeySpec(secretKey.getEncoded(), "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String generateRandomSalt() {
        final byte[] saltBytes = new byte[8];
        final SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(saltBytes);
        return new String(saltBytes, StandardCharsets.UTF_8);
    }
}
