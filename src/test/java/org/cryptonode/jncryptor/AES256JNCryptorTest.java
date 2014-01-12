/*    Copyright 2014 Duncan Jones
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cryptonode.jncryptor;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.junit.Assert;
import org.junit.Test;

/**
 * 
 */
public class AES256JNCryptorTest {

  private static final Random RANDOM = new Random();

  /**
   * Performs a simple round-trip encryption and decryption.
   * 
   * @throws Exception
   */
  @Test
  public void testEncryptionAndDecryption() throws Exception {
    String password = "1234";
    byte[] plaintext = "Hello, World!".getBytes();

    AES256JNCryptor cryptor = new AES256JNCryptor();
    byte[] ciphertext = cryptor.encryptData(plaintext, password.toCharArray());
    byte[] plaintext2 = cryptor.decryptData(ciphertext, password.toCharArray());
    Assert.assertArrayEquals(plaintext, plaintext2);
  }

  /**
   * Creates a valid ciphertext, modifies the MAC and verifies that the
   * decryption fails.
   * 
   * @throws Exception
   */
  @Test(expected = InvalidHMACException.class)
  public void testBrokenHMAC() throws Exception {
    String password = "1234";
    byte[] plaintext = "Hello, World!".getBytes();

    AES256JNCryptor cryptor = new AES256JNCryptor();
    byte[] ciphertext = cryptor.encryptData(plaintext, password.toCharArray());

    // Change one byte in the HMAC
    ciphertext[ciphertext.length - 1] = (byte) (ciphertext[ciphertext.length - 1] + 1);

    cryptor.decryptData(ciphertext, password.toCharArray());
  }

  /**
   * Tests an exception is thrown when the ciphertext is in a bad format.
   * 
   * @throws Exception
   */
  @Test(expected = CryptorException.class)
  public void testBadInput() throws Exception {
    final byte[] nonsenseData = new byte[] { 0x45, 0x55 };
    new AES256JNCryptor().decryptData(nonsenseData, "blah".toCharArray());
  }

  /**
   * Tests an exception is thrown when the iteration count is zero.
   * 
   * @throws Exception
   */
  @Test(expected = IllegalArgumentException.class)
  public void testBadIterations() throws Exception {
    new AES256JNCryptor(0);
  }
  
  /**
   * Tests decryption of a known (v2) ciphertext.
   * 
   * @throws Exception
   */
  @Test
  public void testKnownCiphertext() throws Exception {
    final String password = "P@ssw0rd!";
    final String expectedPlaintextString = "Hello, World! Let's use a few blocks "
        + "with a longer sentence.";

    String knownCiphertext = "02013F194AA9969CF70C8ACB76824DE4CB6CDCF78B7449A87C679FB8EDB6"
        + "A0109C513481DE877F3A855A184C4947F2B3E8FEF7E916E4739F9F889A717FCAF277402866341008A"
        + "09FD3EBAC7FA26C969DD7EE72CFB695547C971A75D8BF1CC5980E0C727BD9F97F6B7489F687813BEB"
        + "94DEB61031260C246B9B0A78C2A52017AA8C92";

    byte[] ciphertext = DatatypeConverter.parseHexBinary(knownCiphertext);

    AES256JNCryptor cryptor = new AES256JNCryptor();
    byte[] plaintext = cryptor.decryptData(ciphertext, password.toCharArray());

    String plaintextString = new String(plaintext, "UTF-8");

    assertEquals(expectedPlaintextString, plaintextString);
  }

  // @Test
  // public void makeKnownCiphertext() throws Exception {
  // final String password = "P@ssw0rd!";
  // final String plaintextString = "Hello, World! Let's use a few blocks "
  // + "with a longer sentence.";
  //
  // final byte[] plaintext = plaintextString.getBytes("US-ASCII");
  //
  // AES256JNCryptor cryptor = new AES256JNCryptor();
  // byte[] ciphertext = cryptor.encryptData(plaintext, password.toCharArray());
  //
  // System.out.println(DatatypeConverter.printHexBinary(plaintext));
  // System.out.println(DatatypeConverter.printHexBinary(ciphertext));
  // }

  /**
   * Tests a {@link NullPointerException} is thrown when the ciphertext is null
   * during decryption.
   * 
   * @throws Exception
   */
  @Test(expected = NullPointerException.class)
  public void testNullCiphertextInDecrypt() throws Exception {
    new AES256JNCryptor().decryptData(null, "blah".toCharArray());
  }

  /**
   * Tests a {@link NullPointerException} is thrown when the plaintext is null
   * during encryption.
   * 
   * @throws Exception
   */
  @Test(expected = NullPointerException.class)
  public void testNullPlaintextInEncrypt() throws Exception {
    new AES256JNCryptor().encryptData(null, "blah".toCharArray());
  }

  /**
   * Performs an encryption followed by a decryption and confirms the data is
   * the same. Uses the key-based methods.
   * 
   * @throws Exception
   */
  @Test
  public void testKeyBasedEncryptionAndDecryption() throws Exception {
    SecretKey encryptionKey = makeRandomAESKey();
    SecretKey hmacKey = makeRandomAESKey();

    final byte[] plaintext = "Hello, World!".getBytes();

    AES256JNCryptor cryptor = new AES256JNCryptor();
    byte[] ciphertext = cryptor.encryptData(plaintext, encryptionKey, hmacKey);
    byte[] newPlaintext = cryptor.decryptData(ciphertext, encryptionKey,
        hmacKey);
    assertArrayEquals(plaintext, newPlaintext);
  }

  private static SecretKey makeRandomAESKey() {
    byte[] keyBytes = new byte[16];
    RANDOM.nextBytes(keyBytes);

    return new SecretKeySpec(keyBytes, "AES");
  }

  /**
   * Checks an exception is thrown when a bad salt length is suggested.
   * 
   * @throws Exception
   */
  @Test(expected = IllegalArgumentException.class)
  public void testBadSaltLengthForKey() throws Exception {
    new AES256JNCryptor().keyForPassword(null,
        new byte[AES256JNCryptor.SALT_LENGTH + 1]);
  }

  /**
   * Tests we return the correct version number.
   * 
   * @throws Exception
   */
  @Test
  public void testVersionNumber() throws Exception {
    assertEquals(3, new AES256JNCryptor().getVersionNumber());
  }

  /**
   * Tests we get an exception if we try to decrypt a key-based ciphertext with
   * a password.
   * 
   * @throws Exception
   */
  @Test(expected = IllegalArgumentException.class)
  public void testDecryptionMismatch() throws Exception {
    SecretKey encryptionKey = makeRandomAESKey();
    SecretKey hmacKey = makeRandomAESKey();

    final byte[] plaintext = "Hello, World!".getBytes();

    AES256JNCryptor cryptor = new AES256JNCryptor();
    byte[] ciphertext = cryptor.encryptData(plaintext, encryptionKey, hmacKey);

    cryptor.decryptData(ciphertext, "whoops!".toCharArray());
  }

  /**
   * Tests we get an exception if we try to set an invalid iteration value.
   * 
   * @throws Exception
   */
  @Test(expected = IllegalArgumentException.class)
  public void testBadIterationValue() throws Exception {
    AES256JNCryptor cryptor = new AES256JNCryptor();
    cryptor.setPBKDFIterations(0);
  }

  /**
   * Tests decryption of a known ciphertext but with the wrong iterations.
   * 
   * @throws Exception
   */
  @Test(expected = InvalidHMACException.class)
  public void testKnownCiphertextWithWrongIterations() throws Exception {
    final String password = "P@ssw0rd!";

    String knownCiphertext = "02013F194AA9969CF70C8ACB76824DE4CB6CDCF78B7449A87C679FB8EDB6"
        + "A0109C513481DE877F3A855A184C4947F2B3E8FEF7E916E4739F9F889A717FCAF277402866341008A"
        + "09FD3EBAC7FA26C969DD7EE72CFB695547C971A75D8BF1CC5980E0C727BD9F97F6B7489F687813BEB"
        + "94DEB61031260C246B9B0A78C2A52017AA8C92";

    byte[] ciphertext = DatatypeConverter.parseHexBinary(knownCiphertext);

    AES256JNCryptor cryptor = new AES256JNCryptor();
    cryptor.setPBKDFIterations(1);
    cryptor.decryptData(ciphertext, password.toCharArray());

  }
}
