package de.catcode.cryptdings;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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

    private static final String AES_GCM_OPERATION_MODE = "AES/GCM/NoPadding";

    public SecretKey deriveFromPassword(final String password, final byte[] salt) {

        try {
            final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            final KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            final SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
            return new SecretKeySpec(secretKey.getEncoded(), "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] generateRandomSalt() {
        // Das Salt wird absichtlich als byte[] durch die Gegen gereicht um Längenprobleme mit dem Encoding zu vermeiden.
        // So können wir sicher sein, dass wir exakt 8 bytes verwenden. Das wird besonders beim Einlesen des Salts bei der Entschlüsselung wichtig.
        final byte[] saltBytes = new byte[8];
        final SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(saltBytes);
        return saltBytes;
    }

    /**
     * Verschlüsselt den Inhalt eines eingehenden InputStreams und schreibt das Resultat auf den gegebenen OutputStream.
     * Es wird eine symmetrische Verschlüsselung (AES) durchgeführt. Als Betriebsmodus wird GCM (Galois Counter Mode) verwendet.
     * <p>
     * Vor das Chiffrat werden das Salt und die IV gehanden. In alternativen Implementierungen könnte man über eine Base64 Kodierung des Salt und der IV nachdenken.
     * Das ist hier aber unnötig.
     * Salt+IV+Cipher
     * <p>
     * Zum Entschlüsseln müssen zuerst das Salt und die IV gelesen werden.
     *
     * @param inputStream  die zu verschlüsselnden Daten als InputStream
     * @param outputStream der OutputStream auf den das Verschlüsselungsergebnis geschrieben werden soll
     * @param secretKey    der {@link SecretKey} der zur Anwendung kommt
     * @param salt         Das zur {@link SecretKey} Erzeugung verwendete Salt.
     */
    public void encrypt(final InputStream inputStream, final OutputStream outputStream, final SecretKey secretKey, final byte[] salt) {

        try {
            // https://en.wikipedia.org/wiki/Galois/Counter_Mode
            // GCM Tag Length kann einer der folgenden Werte sein 128, 120, 112, 104, or 96.
            // Wir nehmen einfach 128
            final IvParameterSpec ivParameterSpec = createRandomIV();
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivParameterSpec.getIV());
            final Cipher cipher = Cipher.getInstance(AES_GCM_OPERATION_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            try (final CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
                // Der write des Salts und des IV muss auf dem outputStream und nicht auf dem cipherOutputStream erfolgen, weil diese nicht verschlüsselt werden sollen.
                outputStream.write(salt);
                outputStream.write(ivParameterSpec.getIV());
                inputStream.transferTo(cipherOutputStream);
            } catch (IOException e) {
                throw new RuntimeException("Unhandled exception occurred.", e);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        }
    }

    /**
     * Entschlüsselt den eigenhenden InputStream und schreibt das Resultat auf den gegebenen OutputStream.
     *
     * @param inputStream  die verschlüsselten Daten als InputStream
     * @param outputStream der OutputStream auf den das Entschlüsselungsergebnis geschrieben werden soll
     * @param password     das Passwort aus welchem, der für die Entschlüsselung benötigte {@link SecretKey} mit dem übermittelten Salt erzeugt werden soll
     */
    public void decrypt(final InputStream inputStream, final OutputStream outputStream, final String password) {

        final byte[] saltBytes = new byte[8];
        final byte[] ivBytes = new byte[12];

        try {
            // man könnte noch überprüfen ob die bytes korrekt gelesen wurden. Ist mir aber erstmal egal.
            // Deswegen meckert Sonar in der IDE
            inputStream.read(saltBytes);
            inputStream.read(ivBytes);
            final SecretKey secretKey = deriveFromPassword(password, saltBytes);
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivBytes);
            final Cipher cipher = Cipher.getInstance(AES_GCM_OPERATION_MODE);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

            try (final CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher)) {
                cipherInputStream.transferTo(outputStream);
            } catch (IOException e) {
                throw new RuntimeException("Unhandled exception occurred.", e);
            }
        } catch (IOException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Unhandled exception occurred.", e);
        }
    }

    private IvParameterSpec createRandomIV() {
        // Da wir die nonce nur für GCM in diesem Beispiel verwenden ist die Länge des Arrays 12. Bei GCM ist diese 12, bei CBC 16.
        final byte[] nonce = new byte[12];
        // man könnt den SecureRandom mit SHA1PRNG explizit erzeugen, jedoch ist das sowieso einer der Defaults.
        // SecureRandom.getInstance("SHA1PRNG")
        final SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(nonce);
        return new IvParameterSpec(nonce);
    }
}
