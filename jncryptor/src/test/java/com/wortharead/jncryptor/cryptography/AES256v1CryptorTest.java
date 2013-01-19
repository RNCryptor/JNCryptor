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

package com.wortharead.jncryptor.cryptography;

import javax.xml.bind.DatatypeConverter;

import org.junit.Assert;
import org.junit.Test;

import com.wortharead.jncryptor.cryptography.AES256v1Cryptor;
import com.wortharead.jncryptor.cryptography.CryptorException;
import com.wortharead.jncryptor.cryptography.InvalidHMACException;

/**
 * 
 */
public class AES256v1CryptorTest {

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
   * Quick test to produce values to compare implementations.
   * 
   * @throws Exception
   */
  @Test
  public void testValuePrinting() throws Exception {
    final String password = "P@ssw0rd!";
    final String plaintextString = "Hello, World! Let's use a few blocks with a longer sentence.";
    final byte[] plaintextBytes = plaintextString.getBytes();
    AES256v1Cryptor cryptor = new AES256v1Cryptor();
    byte[] ciphertext = cryptor.encryptData(plaintextBytes,
        password.toCharArray());

    System.out.println(String.format("Password: %s", password));
    System.out
        .println(String.format("Plaintext (string): %s", plaintextString));
    System.out.println(String.format("Plaintext (bytes): %s",
        DatatypeConverter.printHexBinary(plaintextBytes)));
    System.out.println(String.format("Ciphertext: %s",
        DatatypeConverter.printHexBinary(ciphertext)));
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
}
