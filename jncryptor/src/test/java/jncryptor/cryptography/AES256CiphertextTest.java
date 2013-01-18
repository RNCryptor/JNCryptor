package jncryptor.cryptography;

import static org.junit.Assert.assertEquals;

import java.util.Random;

import org.junit.Test;

/**
 * 
 */
public class AES256CiphertextTest {

  /**
   * Some simple random data of the correct size.
   */
  private static class ExampleData {
    private static final byte[] ENCRYPTION_SALT = new byte[AES256Ciphertext.ENCRYPTION_SALT_LENGTH];
    private static final byte[] HMAC_SALT = new byte[AES256Ciphertext.HMAC_SALT_LENGTH];
    private static final byte[] IV = new byte[AES256Ciphertext.AES_BLOCK_SIZE];
    private static final byte[] CIPHERTEXT = new byte[AES256Ciphertext.AES_BLOCK_SIZE];
    private static final byte[] HMAC = new byte[AES256Ciphertext.HMAC_SIZE];

    static {
      Random random = new Random();
      random.nextBytes(ENCRYPTION_SALT);
      random.nextBytes(HMAC_SALT);
      random.nextBytes(IV);
      random.nextBytes(CIPHERTEXT);
      random.nextBytes(HMAC);
    }
  }

  @Test
  public void circularTest() throws Exception {

    AES256Ciphertext data = new AES256Ciphertext(ExampleData.ENCRYPTION_SALT,
        ExampleData.HMAC_SALT, ExampleData.IV, ExampleData.CIPHERTEXT,
        ExampleData.HMAC);

    byte[] rawData = data.getRawData();

    AES256Ciphertext data2 = new AES256Ciphertext(rawData);

    assertEquals(data, data2);
  }

  @Test(expected = NullPointerException.class)
  public void testNPE() throws Exception {
    new AES256Ciphertext(null);
  }

  @Test(expected = InvalidDataException.class)
  public void testMinimumLength() throws Exception {

    // data is one byte short of minimum
    byte[] data = new byte[AES256Ciphertext.MINIMUM_LENGTH_WITH_PASSWORD - 1];
    new AES256Ciphertext(data);
  }

  @Test(expected = InvalidDataException.class)
  public void testZeroVersion() throws Exception {
    byte[] data = new byte[AES256Ciphertext.MINIMUM_LENGTH_WITH_PASSWORD];
    new AES256Ciphertext(data);
  }

  @Test(expected = InvalidDataException.class)
  public void testNonZeroOption() throws Exception {
    byte[] data = new byte[AES256Ciphertext.MINIMUM_LENGTH_WITH_PASSWORD];
    data[0] = 1; // Version 1 = correct
    data[1] = 1; // Options = 1 (incorrect)

    new AES256Ciphertext(data);
  }

  @Test
  public void testSimple() throws Exception {
    byte[] data = new byte[AES256Ciphertext.MINIMUM_LENGTH_WITH_PASSWORD];
    data[0] = 1; // Version 1 = correct

    new AES256Ciphertext(data);
  }
}
