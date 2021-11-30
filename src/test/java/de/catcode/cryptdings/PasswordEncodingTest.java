package de.catcode.cryptdings;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

class PasswordEncodingTest {

    @Test
    void testPasswordEncoding() throws UnsupportedEncodingException {
        // Print benutztes Charset. Über die IDE ausgeführt ist das UTF-8.
        // Je nachdem, wie man das Surefire Plugin einstellt wird unter Windows
        // Cp1252
        // windows-1252
        // ausgegeben.
        System.out.println(System.getProperty("file.encoding"));
        System.out.println(Charset.defaultCharset());
//        System.setProperty("file.encoding", StandardCharsets.UTF_8.toString());
//        System.out.println(System.getProperty("file.encoding"));
        final PrintStream printStream = new PrintStream(System.out, true, System.getProperty("file.encoding"));

        final ByteBuffer utf8ByteBuffer = StandardCharsets.UTF_8.encode("testäöü");
        final ByteBuffer asciiByteBuffer = StandardCharsets.US_ASCII.encode("testäöü");

        final String utf8String = StandardCharsets.UTF_8.decode(utf8ByteBuffer).toString();
        final String asciiString = StandardCharsets.US_ASCII.decode(asciiByteBuffer).toString();

        Assertions.assertNotEquals(utf8String, asciiString);

        // Man wird bei der Ausgabe sehen können, dass bei Ascii die Umlaute kaputt sind.
        printStream.println(utf8String);
        printStream.println(asciiString);

        // Sind denn die bytes gleich, wenn man sie entsprechend ihres encodings aus dem String zieht?
//        Assertions.assertArrayEquals(utf8String.getBytes(StandardCharsets.UTF_8), asciiString.getBytes(StandardCharsets.US_ASCII));
        // Nein sind sie nicht, da die Umlaute bei der Konvertierung in ASCII verloren gegangen sind.
        // Deswegen ist der utf8 Byte Array 10 Felder lang und der ascii Array nur 7, da bei Unicode für deutsche Umlaute 2 Bytes benötigt werden.
        // Im Fall der ascii Kodierung steht jedoch nur ein Byte zu Verfügung wodurch auch keine Umlaute etc... darstellbar sind.


    }
}
