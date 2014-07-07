package org.cryptonode.jncryptor;

import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Random;
import java.util.UUID;

import org.junit.Ignore;
import org.junit.Test;

public class AES256JNCryptorOutputStreamTest {

  private static final int MAX_SIZE = 2 * 1024 * 1024;
  private static final int TEST_ITERATIONS = 100;
  private final Random random = new Random();
  private final JNCryptor cryptor = new AES256JNCryptor();


  @Test
  public void testRandomEncryption() throws IOException, CryptorException {
    byte[] startData = new byte[random.nextInt(MAX_SIZE) + 1];
    random.nextBytes(startData);
    char[] password = UUID.randomUUID().toString().toCharArray();

    ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream();
    AES256JNCryptorOutputStream os = new AES256JNCryptorOutputStream(encryptedStream, password);
    os.write(startData);
    os.flush();
    os.close();

    byte[] cipherText = encryptedStream.toByteArray();
    byte[] plainText = cryptor.decryptData(cipherText, password);
    assertArrayEquals("Decrypted data doesn't match original data!", startData, plainText);
  }

  @Ignore("heavy test")
  @Test
  public void testEncryptionALot() throws IOException, CryptorException {
    for (int i = 0; i < TEST_ITERATIONS; i++) {
      System.out.print(i + ", ");
      testRandomEncryption();
    }
    System.out.println();
  }
}
