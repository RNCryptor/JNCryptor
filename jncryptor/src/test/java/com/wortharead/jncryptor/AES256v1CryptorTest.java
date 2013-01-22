/*    Copyright 2013 Duncan Jones
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

package com.wortharead.jncryptor;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.io.Charsets;
import org.junit.Assert;
import org.junit.Test;

/**
 * 
 */
public class AES256v1CryptorTest {

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

    AES256v1Cryptor cryptor = new AES256v1Cryptor();
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

    AES256v1Cryptor cryptor = new AES256v1Cryptor();
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
    new AES256v1Cryptor().decryptData(nonsenseData, "blah".toCharArray());
  }

  /**
   * Tests decryption of a known ciphertext.
   * 
   * @throws Exception
   */
  @Test
  public void testKnownCiphertext() throws Exception {
    final String password = "P@ssw0rd!";
    final String expectedPlaintextString = "Hello, World! Let's use a few blocks "
        + "with a longer sentence.";

    // This known value has been confirmed with Rob Napier
    String knownCiphertext = "0101EF297BCD83B68AF69FC4B7040A0E5EB9F349EFAF051030748FD1"
        + "9AAA4362E9D6F4FCADC4EFDBC3EBA1B6251BA8ADAC668425523887BAA3334A01F4450A4BF6F80CA3"
        + "FFED1408D7EB7DE0254665EC387C43D5AEE0ADFF9CB7A9E939E196E071ACBC4A1E7E09F15502D937"
        + "9D307F66C4A0D22FE8731E3A69872355BD38C7967355";

    byte[] ciphertext = DatatypeConverter.parseHexBinary(knownCiphertext);

    AES256v1Cryptor cryptor = new AES256v1Cryptor();
    byte[] plaintext = cryptor.decryptData(ciphertext, password.toCharArray());

    String plaintextString = new String(plaintext, Charsets.UTF_8);

    assertEquals(expectedPlaintextString, plaintextString);
  }

  /**
   * Tests a {@link NullPointerException} is thrown when the ciphertext is null
   * during decryption.
   * 
   * @throws Exception
   */
  @Test(expected = NullPointerException.class)
  public void testNullCiphertextInDecrypt() throws Exception {
    new AES256v1Cryptor().decryptData(null, "blah".toCharArray());
  }

  /**
   * Tests a {@link NullPointerException} is thrown when the plaintext is null
   * during encryption.
   * 
   * @throws Exception
   */
  @Test(expected = NullPointerException.class)
  public void testNullPlaintextInEncrypt() throws Exception {
    new AES256v1Cryptor().encryptData(null, "blah".toCharArray());
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

    AES256v1Cryptor cryptor = new AES256v1Cryptor();
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
    new AES256v1Cryptor().keyForPassword(null,
        new byte[AES256v1Cryptor.SALT_LENGTH + 1]);
  }

  /**
   * Tests we return the correct version number.
   * 
   * @throws Exception
   */
  @Test
  public void testVersionNumber() throws Exception {
    assertEquals(1, new AES256v1Cryptor().getVersionNumber());
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

    AES256v1Cryptor cryptor = new AES256v1Cryptor();
    byte[] ciphertext = cryptor.encryptData(plaintext, encryptionKey, hmacKey);
    
    cryptor.decryptData(ciphertext, "whoops!".toCharArray());
  }
}
