package org.cryptonode.jncryptor;

import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Random;
import java.util.UUID;

import org.junit.Ignore;
import org.junit.Test;

public class AES256JNCryptorInputStreamTest {

    private static final int MAX_SIZE = 2 * 1024 * 1024;
    private static final int TEST_ITERATIONS = 100;
    private final Random random = new Random();
    private final JNCryptor cryptor = new AES256JNCryptor();

    /**
     * Tests decryption of a random byte array of max length {@value #MAX_SIZE}, with a random
     * UUID as a password. Encryption is done by the {@link JNCryptor} reference implementation.
     */
    @Test
    public void testRandomDecryption() throws Exception {
        byte[] startData = new byte[random.nextInt(MAX_SIZE) + 1];
        random.nextBytes(startData);
        char[] password = UUID.randomUUID().toString().toCharArray();
        byte[] ciphertext = cryptor.encryptData(startData, password);

        InputStream is = new AES256JNCryptorInputStream(new ByteArrayInputStream(ciphertext), password);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = is.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        is.close();

        byte[] result = baos.toByteArray();
        assertArrayEquals("Decrypted data doesn't match encrypted data!", startData, result);
    }

    @Ignore("heavy test")
    @Test
    public void testDecryptionALot() throws Exception {
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            System.out.print(i + ", ");
            testRandomDecryption();
        }
        System.out.println();
    }
}
