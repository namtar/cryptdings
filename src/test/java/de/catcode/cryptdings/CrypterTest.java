package de.catcode.cryptdings;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

class CrypterTest {

    private Crypter crypter = new Crypter();

    @Test
    void testSecretKeyGeneration() {

        // festes Salt für Tests. Das muss produktiv random sein.
        final byte[] salt = "testSalt".getBytes(StandardCharsets.UTF_8); // 8 bytes
        Assertions.assertTrue(salt.length == 8);

        final SecretKey secretKey = crypter.deriveFromPassword("test123", salt);
        final SecretKey sameSecretKey = crypter.deriveFromPassword("test123", salt);

        // bei gleicher Eingabe kommt der gleiche SecretKey raus.
        Assertions.assertArrayEquals(secretKey.getEncoded(), sameSecretKey.getEncoded());
        System.out.println(Base64.getEncoder().encodeToString(salt));
    }

    @Test
    void testEncryptAndDecrypt() {
        final byte[] randomSalt = crypter.generateRandomSalt();
        final SecretKey secretKey = crypter.deriveFromPassword("test123", randomSalt);
        final String testContent = getTestContent();

        System.out.println("Salt: " + HexFormat.of().formatHex(randomSalt));

        final ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream();

        crypter.encrypt(new ByteArrayInputStream(testContent.getBytes(StandardCharsets.UTF_8)), encryptedOutputStream, secretKey, randomSalt);

        final InputStream encryptedInputStream = new ByteArrayInputStream(encryptedOutputStream.toByteArray());
        final ByteArrayOutputStream decryptedOutputStream = new ByteArrayOutputStream();
        crypter.decrypt(encryptedInputStream, decryptedOutputStream, "test123");

        Assertions.assertEquals(testContent, decryptedOutputStream.toString());

    }

    private String getTestContent() {
        return """
                Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. A erat nam at lectus urna duis convallis convallis. Ultricies lacus sed turpis tincidunt id. Sagittis nisl rhoncus mattis rhoncus urna neque. Dui vivamus arcu felis bibendum. Nascetur ridiculus mus mauris vitae ultricies. Eros in cursus turpis massa. Ipsum dolor sit amet consectetur. Arcu non odio euismod lacinia at quis. Consequat nisl vel pretium lectus quam id leo.
                                
                A diam sollicitudin tempor id eu. Ante in nibh mauris cursus mattis molestie a iaculis. Gravida neque convallis a cras semper auctor neque vitae. Augue eget arcu dictum varius duis at consectetur lorem. Nisi porta lorem mollis aliquam ut porttitor leo a diam. Non nisi est sit amet. Rhoncus dolor purus non enim. Risus commodo viverra maecenas accumsan lacus vel facilisis volutpat. Massa tempor nec feugiat nisl pretium fusce id velit ut. Nam aliquam sem et tortor. Commodo elit at imperdiet dui accumsan sit amet nulla facilisi. Tempus iaculis urna id volutpat lacus. Et netus et malesuada fames ac turpis. Enim nunc faucibus a pellentesque sit amet. Morbi enim nunc faucibus a pellentesque sit amet porttitor eget. Cursus risus at ultrices mi tempus imperdiet nulla. Felis donec et odio pellentesque diam volutpat commodo. Faucibus pulvinar elementum integer enim. Neque convallis a cras semper.
                                
                Eros in cursus turpis massa tincidunt. Fames ac turpis egestas sed tempus urna et pharetra pharetra. Quam id leo in vitae turpis massa. Dolor sed viverra ipsum nunc aliquet bibendum enim facilisis gravida. Scelerisque eleifend donec pretium vulputate sapien. Bibendum est ultricies integer quis auctor elit sed vulputate mi. A diam sollicitudin tempor id eu. Placerat in egestas erat imperdiet sed euismod nisi porta lorem. Pretium vulputate sapien nec sagittis aliquam malesuada bibendum arcu. Mauris vitae ultricies leo integer malesuada nunc vel. Commodo nulla facilisi nullam vehicula. Pretium viverra suspendisse potenti nullam ac tortor vitae. Quisque id diam vel quam elementum. Purus sit amet volutpat consequat mauris nunc congue nisi vitae. Bibendum at varius vel pharetra vel turpis nunc eget. Amet nisl purus in mollis nunc sed id semper risus. Mauris sit amet massa vitae.
                                
                Non blandit massa enim nec dui nunc mattis enim. Urna condimentum mattis pellentesque id nibh tortor id aliquet. Et netus et malesuada fames ac. Nec tincidunt praesent semper feugiat nibh sed. Dolor sit amet consectetur adipiscing elit. Pharetra massa massa ultricies mi quis hendrerit dolor magna eget. Mauris in aliquam sem fringilla ut. Faucibus nisl tincidunt eget nullam non nisi est sit amet. Integer enim neque volutpat ac tincidunt vitae semper quis lectus. Sed blandit libero volutpat sed cras ornare. Sed ullamcorper morbi tincidunt ornare. Ac turpis egestas maecenas pharetra convallis.
                                
                Imperdiet sed euismod nisi porta lorem mollis. Enim sit amet venenatis urna. Mauris pellentesque pulvinar pellentesque habitant. Arcu bibendum at varius vel. Vehicula ipsum a arcu cursus vitae congue. Aliquet sagittis id consectetur purus. Porta lorem mollis aliquam ut porttitor leo a diam. Rhoncus aenean vel elit scelerisque. Cras adipiscing enim eu turpis egestas pretium aenean pharetra magna. Sed cras ornare arcu dui. Et malesuada fames ac turpis egestas sed tempus urna. Ultricies mi quis hendrerit dolor magna eget est lorem ipsum. Pretium lectus quam id leo in vitae. Tempor orci eu lobortis elementum nibh. Ipsum nunc aliquet bibendum enim facilisis gravida neque convallis a. In eu mi bibendum neque egestas congue. In aliquam sem fringilla ut. Arcu cursus euismod quis viverra nibh cras pulvinar.
                                
                At tellus at urna condimentum mattis pellentesque id nibh. Mauris a diam maecenas sed enim ut. Leo vel orci porta non pulvinar neque laoreet suspendisse. Et malesuada fames ac turpis. A erat nam at lectus urna duis convallis. Eget sit amet tellus cras adipiscing enim. Etiam erat velit scelerisque in dictum non. Risus viverra adipiscing at in tellus integer. Suspendisse ultrices gravida dictum fusce ut placerat orci nulla. Imperdiet dui accumsan sit amet. Massa enim nec dui nunc mattis enim ut tellus elementum. Nisi scelerisque eu ultrices vitae auctor. Convallis tellus id interdum velit laoreet id donec ultrices tincidunt. Mauris vitae ultricies leo integer malesuada nunc. Euismod elementum nisi quis eleifend quam adipiscing vitae proin sagittis. Tincidunt augue interdum velit euismod in pellentesque massa.
                                
                Enim diam vulputate ut pharetra sit amet aliquam id. Risus sed vulputate odio ut enim. Magna fringilla urna porttitor rhoncus dolor purus non enim praesent. Neque gravida in fermentum et sollicitudin ac. Molestie ac feugiat sed lectus. Praesent tristique magna sit amet purus gravida quis blandit. Lobortis feugiat vivamus at augue. Volutpat diam ut venenatis tellus. Elit pellentesque habitant morbi tristique senectus et netus et. Neque egestas congue quisque egestas diam in arcu cursus. Bibendum ut tristique et egestas quis ipsum suspendisse ultrices. Tristique magna sit amet purus gravida quis. Elementum curabitur vitae nunc sed velit dignissim sodales. At augue eget arcu dictum varius duis at. Quis vel eros donec ac odio tempor orci dapibus. Et malesuada fames ac turpis egestas sed tempus.
                                
                Venenatis a condimentum vitae sapien. Aliquet lectus proin nibh nisl condimentum id venenatis. Venenatis cras sed felis eget velit aliquet sagittis id consectetur. Pellentesque habitant morbi tristique senectus et netus et malesuada fames. Quis blandit turpis cursus in hac habitasse platea dictumst quisque. Condimentum lacinia quis vel eros donec ac odio tempor. Nibh praesent tristique magna sit amet purus gravida quis blandit. Lorem ipsum dolor sit amet consectetur adipiscing. At elementum eu facilisis sed odio. Leo integer malesuada nunc vel. Lacus vel facilisis volutpat est velit egestas dui id ornare. Vitae tempus quam pellentesque nec nam aliquam. Tristique senectus et netus et malesuada fames ac turpis. Viverra mauris in aliquam sem fringilla ut morbi. Facilisis sed odio morbi quis commodo odio aenean sed. Netus et malesuada fames ac turpis egestas sed. Amet consectetur adipiscing elit ut. Sagittis vitae et leo duis. Bibendum est ultricies integer quis auctor elit sed vulputate mi.
                                
                Suspendisse potenti nullam ac tortor vitae purus faucibus. Tristique sollicitudin nibh sit amet commodo nulla facilisi. Risus at ultrices mi tempus imperdiet nulla malesuada pellentesque elit. Turpis egestas maecenas pharetra convallis posuere morbi leo urna molestie. Aenean pharetra magna ac placerat vestibulum. Ut aliquam purus sit amet luctus venenatis lectus magna. Posuere lorem ipsum dolor sit amet consectetur adipiscing elit. Mattis nunc sed blandit libero. Penatibus et magnis dis parturient montes nascetur ridiculus mus mauris. Turpis tincidunt id aliquet risus feugiat. Tellus molestie nunc non blandit. Auctor urna nunc id cursus metus aliquam eleifend mi. Amet consectetur adipiscing elit pellentesque habitant. Eros in cursus turpis massa tincidunt dui ut ornare. Augue ut lectus arcu bibendum at varius vel pharetra vel.
                                
                Tortor condimentum lacinia quis vel eros donec. Tellus in hac habitasse platea dictumst. Nunc vel risus commodo viverra. Lectus quam id leo in vitae turpis. Pharetra vel turpis nunc eget lorem dolor sed viverra ipsum. Morbi tristique senectus et netus et malesuada fames. Pharetra et ultrices neque ornare aenean euismod elementum nisi. Dolor purus non enim praesent elementum facilisis leo. Sit amet purus gravida quis blandit. In fermentum et sollicitudin ac orci. Pharetra vel turpis nunc eget lorem dolor sed. Sed vulputate odio ut enim blandit volutpat. Sapien faucibus et molestie ac feugiat sed. Nullam vehicula ipsum a arcu cursus vitae congue. Volutpat sed cras ornare arcu dui vivamus arcu felis. Convallis tellus id interdum velit. Commodo ullamcorper a lacus vestibulum sed arcu non odio euismod. Etiam non quam lacus suspendisse faucibus. Lectus mauris ultrices eros in. A cras semper auctor neque vitae tempus quam pellentesque nec.
                """;
    }
}
