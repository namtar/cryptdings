package de.catcode.cryptdings;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CrypterTest {

    private Crypter crypter = new Crypter();

    @Test
    void testSecretKeyGeneration() {

        // festes Salt für Tests. Das muss produktiv random sein.
        final String salt = "testSalt"; // 8 bytes

        final SecretKey secretKey = crypter.deriveFromPassword("test123", salt);
        final SecretKey sameSecretKey = crypter.deriveFromPassword("test123", salt);

        // bei gleicher Eingabe kommt der gleiche SecretKey raus.
        Assertions.assertArrayEquals(secretKey.getEncoded(), sameSecretKey.getEncoded());

        // Ein Salt, welches aus Zeichen besteht, die auf ein Byte kodiert werden können erzeugt einen Base64 String der 12 Zeichen lang ist.
        // Umlaute etc... verlängern diesen String.
        // Da i.d.R ein Salt Random generiert wird nimmt es eine feste Länge von 8 bytes ein, die Base64 kodiert eine Länge von 12 haben.
        System.out.println(Base64.getEncoder().encodeToString(salt.getBytes(StandardCharsets.UTF_8)));
    }
}
