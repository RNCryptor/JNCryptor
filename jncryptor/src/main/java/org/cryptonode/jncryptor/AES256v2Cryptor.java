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

package org.cryptonode.jncryptor;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.Validate;

/**
 * This {@link JNCryptor} instance produces data in version 2 format.
 * <p>
 * 
 * <pre>
 * | version | options | encryption salt | HMAC salt |   IV   | ... ciphertext ... |     HMAC    |
 * |    0    |    1    |       2->9      |   10->17  | 18->33 | <-      ...     -> | (n-32) -> n |
 * </pre>
 * 
 * <ul>
 * <li><b>version</b> (1 byte): Data format version. Always {@code 0x02}.</li>
 * <li><b>options</b> (1 byte): {@code 0x00} if keys are used, {@code 0x01} if a
 * password is used.</li>
 * <li><b>encryption salt</b> (8 bytes)</li>
 * <li><b>HMAC salt</b> (8 bytes)</li>
 * <li><b>IV</b> (16 bytes)</li>
 * <li><b>ciphertext</b> (variable): 256-bit AES encrypted, CBC-mode with
 * PKCS&nbsp;#5 padding.</li>
 * <li><b>HMAC</b> (32 bytes)</li>
 * </ul>
 * 
 * <p>
 * The encryption key is derived using the PKBDF2 function, using a random
 * eight-byte encryption salt, the supplied password and 10,000 iterations. The
 * HMAC key is derived in a similar fashion, using it's own random eight-byte
 * HMAC salt. Both salt values are stored in the ciphertext output (as shown
 * above).
 * 
 * <p>
 * The ciphertext is AES-256-CBC encrypted, using a randomly generated IV and
 * the encryption key (described above), with PKCS&nbsp;#5 padding.
 * <p>
 * The HMAC is calculated across all the data (except the HMAC itself, of
 * course), generated using the HMAC key described above and the SHA-256 PRF.
 * <p>
 * See <a
 * href="https://github.com/rnapier/RNCryptor/wiki/Data-Format">https://github
 * .com/rnapier/RNCryptor/wiki/Data-Format</a>, from which most of the
 * information above was shamelessly copied.
 */
public class AES256v2Cryptor implements JNCryptor {

  private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final String AES_NAME = "AES";
  private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA1";
  private static final int PBKDF_DEFAULT_ITERATIONS = 10000;
  private static final int VERSION = 2;
  private static final int AES_256_KEY_SIZE = 256 / 8;
  private static final int AES_BLOCK_SIZE = 16;

  // Salt length exposed as package private to aid unit testing
  static final int SALT_LENGTH = 8;

  // SecureRandom is threadsafe
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private int iterations = PBKDF_DEFAULT_ITERATIONS;

  static {
    // Register this class with the factory
    JNCryptorFactory.registerCryptor(VERSION, new AES256v2Cryptor());
  }

  /**
   * This class should be accessed only via
   * {@link JNCryptorFactory#getCryptor()}, except for unit testing.
   */
  AES256v2Cryptor() {
  }

  @Override
  public SecretKey keyForPassword(char[] password, byte[] salt)
      throws CryptorException {

    Validate.notNull(salt, "Salt value cannot be null.");
    Validate.isTrue(salt.length == SALT_LENGTH, "Salt value must be %d bytes.",
        SALT_LENGTH);

    try {
      SecretKeyFactory factory = SecretKeyFactory
          .getInstance(KEY_DERIVATION_ALGORITHM);
      SecretKey tmp = factory.generateSecret(new PBEKeySpec(password, salt,
          getIterations(), AES_256_KEY_SIZE * 8));
      return new SecretKeySpec(tmp.getEncoded(), AES_NAME);
    } catch (GeneralSecurityException e) {
      throw new CryptorException(String.format(
          "Failed to generate key from password using %s.",
          KEY_DERIVATION_ALGORITHM), e);
    }
  }

  /**
   * @return the number of iterations to use for PBDKF2
   */
  private synchronized int getIterations() {
    return iterations;
  }

  @Override
  public synchronized void setPBKDFIterations(int iterations) {
    Validate.isTrue(iterations > 0,
        "Number of iterations must be greater than zero.");

    this.iterations = iterations;
  }

  /**
   * Decrypts data.
   * 
   * @param aesCiphertext
   *          the ciphertext from the message
   * @param decryptionKey
   *          the key to decrypt
   * @param hmacKey
   *          the key to recalculate the HMAC
   * @return the decrypted data
   * @throws CryptorException
   *           if a JCE error occurs
   */
  private byte[] decryptData(AES256v2Ciphertext aesCiphertext,
      SecretKey decryptionKey, SecretKey hmacKey) throws CryptorException {

    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(hmacKey);
      byte[] hmacValue = mac.doFinal(aesCiphertext.getDataToHMAC());

      if (!Arrays.equals(hmacValue, aesCiphertext.getHmac())) {
        throw new InvalidHMACException("Incorrect HMAC value.");
      }

      Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(
          aesCiphertext.getIv()));

      return cipher.doFinal(aesCiphertext.getCiphertext());
    } catch (InvalidKeyException e) {
      throw new CryptorException(
          "Caught InvalidKeyException. Do you have unlimited strength jurisdiction files installed?",
          e);
    } catch (GeneralSecurityException e) {
      throw new CryptorException("Failed to decrypt message.", e);
    }
  }

  @Override
  public byte[] decryptData(byte[] ciphertext, char[] password)
      throws CryptorException {
    Validate.notNull(ciphertext, "Ciphertext cannot be null.");

    try {
      AES256v2Ciphertext aesCiphertext = new AES256v2Ciphertext(ciphertext);

      if (!aesCiphertext.isPasswordBased()) {
        throw new IllegalArgumentException(
            "Ciphertext was not encrypted with a password.");
      }

      SecretKey decryptionKey = keyForPassword(password,
          aesCiphertext.getEncryptionSalt());
      SecretKey hmacKey = keyForPassword(password, aesCiphertext.getHmacSalt());

      return decryptData(aesCiphertext, decryptionKey, hmacKey);
    } catch (InvalidDataException e) {
      throw new CryptorException("Unable to parse ciphertext.", e);
    }
  }

  /**
   * Encrypts plaintext data, 256-bit AES CBC-mode with PKCS#5 padding.
   * 
   * @param plaintext
   *          the plaintext
   * @param password
   *          the password (can be <code>null</code> or empty)
   * @param encryptionSalt
   *          eight bytes of random salt value
   * @param hmacSalt
   *          eight bytes of random salt value
   * @param iv
   *          sixteen bytes of AES IV
   * @return a formatted ciphertext
   * @throws CryptorException
   *           if an error occurred
   */
  byte[] encryptData(byte[] plaintext, char[] password, byte[] encryptionSalt,
      byte[] hmacSalt, byte[] iv) throws CryptorException {

    SecretKey encryptionKey = keyForPassword(password, encryptionSalt);
    SecretKey hmacKey = keyForPassword(password, hmacSalt);

    try {
      Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
      byte[] ciphertext = cipher.doFinal(plaintext);

      AES256v2Ciphertext output = new AES256v2Ciphertext(encryptionSalt,
          hmacSalt, iv, ciphertext);

      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(hmacKey);
      byte[] hmac = mac.doFinal(output.getDataToHMAC());
      output.setHmac(hmac);
      return output.getRawData();

    } catch (InvalidKeyException e) {
      throw new CryptorException(
          "Caught InvalidKeyException. Do you have unlimited strength jurisdiction files installed?",
          e);
    } catch (GeneralSecurityException e) {
      throw new CryptorException("Failed to generate ciphertext.", e);
    }
  }

  @Override
  public byte[] encryptData(byte[] plaintext, char[] password)
      throws CryptorException {
    Validate.notNull(plaintext, "Plaintext cannot be null.");

    byte[] encryptionSalt = getSecureRandomData(SALT_LENGTH);
    byte[] hmacSalt = getSecureRandomData(SALT_LENGTH);
    byte[] iv = getSecureRandomData(AES_BLOCK_SIZE);

    return encryptData(plaintext, password, encryptionSalt, hmacSalt, iv);
  }

  /**
   * Returns random data supplied by this class' {@link SecureRandom} instance.
   * 
   * @param length
   *          the number of bytes to return
   * @return random bytes
   */
  private static byte[] getSecureRandomData(int length) {
    byte[] result = new byte[length];
    SECURE_RANDOM.nextBytes(result);
    return result;
  }

  @Override
  public int getVersionNumber() {
    return VERSION;
  }

  @Override
  public byte[] decryptData(byte[] ciphertext, SecretKey decryptionKey,
      SecretKey hmacKey) throws CryptorException, InvalidHMACException {

    Validate.notNull(ciphertext, "Ciphertext cannot be null.");
    Validate.notNull(decryptionKey, "Decryption key cannot be null.");
    Validate.notNull(hmacKey, "HMAC key cannot be null.");

    AES256v2Ciphertext aesCiphertext;
    try {
      aesCiphertext = new AES256v2Ciphertext(ciphertext);

      return decryptData(aesCiphertext, decryptionKey, hmacKey);

    } catch (InvalidDataException e) {
      throw new CryptorException("Unable to parse ciphertext.", e);
    }
  }

  @Override
  public byte[] encryptData(byte[] plaintext, SecretKey encryptionKey,
      SecretKey hmacKey) throws CryptorException {

    Validate.notNull(plaintext, "Plaintext cannot be null.");
    Validate.notNull(encryptionKey, "Encryption key cannot be null.");
    Validate.notNull(hmacKey, "HMAC key cannot be null.");

    byte[] iv = getSecureRandomData(AES_BLOCK_SIZE);

    try {
      Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
      byte[] ciphertext = cipher.doFinal(plaintext);

      AES256v2Ciphertext output = new AES256v2Ciphertext(iv, ciphertext);

      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(hmacKey);
      byte[] hmac = mac.doFinal(output.getDataToHMAC());
      output.setHmac(hmac);
      return output.getRawData();

    } catch (GeneralSecurityException e) {
      throw new CryptorException("Failed to generate ciphertext.", e);
    }
  }

}
