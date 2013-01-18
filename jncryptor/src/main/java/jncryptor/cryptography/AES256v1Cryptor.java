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

package jncryptor.cryptography;

import java.security.GeneralSecurityException;
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
 * This {@link JNCryptor} instance produces data in the following (version 1)
 * format:
 * 
 * <pre>
 * |     version     | options | encryptionSalt | HMACSalt |  IV   | ... ciphertext ... |   HMAC   |
 * |        0        |    1    |      2-9       |  10-17   | 18-33 | <-      ...     -> | n-32 - n |
 * </pre>
 * 
 * <ul>
 * <li>version (1 byte): Data format version. Always {@code 0x01}.</li>
 * <li>options (1 byte): Reserved. Always {@code 0x00}.</li>
 * <li>encryptionSalt (8 bytes)</li>
 * <li>HMACSalt (8 bytes)</li>
 * <li>IV (16 bytes)</li>
 * <li>ciphertext (variable): 256-bit AES encrypted, CBC-mode with PKCS&nbsp;#5
 * padding.</li>
 * <li>HMAC (32 bytes)</li>
 * </ul>
 * 
 * <h3>Details</h3>
 * 
 * <p>
 * EncryptionKey = PKBDF2(encryptionSalt, 10k iterations, password)
 * </p>
 * <p>
 * HMACKey = PKBDF2(HMACSalt, 10k iterations, password)
 * </p>
 * <p>
 * Ciphertext is AES-256-CBC encrypted using the given IV and the EncryptionKey
 * (above), with PKCS&nbsp;#5 padding.
 * </p>
 * <p>
 * HMAC is generated using the ciphertext and the HMACKey (above) and the
 * SHA-256 PRF.
 * </p>
 * 
 * @see https://github.com/rnapier/RNCryptor/wiki/Data-Format, from which most
 *      of the information above was shamelessly copied
 */
public class AES256v1Cryptor implements JNCryptor {

  private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final String AES_NAME = "AES";
  private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA1";
  private static final int PBKDF_ITERATIONS = 10000;
  private static final int VERSION = 1;
  private static final int AES_256_KEY_SIZE = 256 / 8;
  private static final int AES_BLOCK_SIZE = 16;
  private static final int SALT_LENGTH = 8;

  // SecureRandom is threadsafe
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  static {
    // Register this class with the factory
    JNCryptorFactory.registerCryptor(VERSION, new AES256v1Cryptor());
  }

  /**
   * This class should be accessed only via
   * {@link JNCryptorFactory#getCryptor()}, except for unit testing.
   */
  AES256v1Cryptor() {
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
          PBKDF_ITERATIONS, AES_256_KEY_SIZE * 8));
      return new SecretKeySpec(tmp.getEncoded(), AES_NAME);
    } catch (GeneralSecurityException e) {
      throw new CryptorException(String.format(
          "Failed to generate key from password using %s.",
          KEY_DERIVATION_ALGORITHM), e);
    }
  }

  @Override
  public byte[] decryptData(byte[] ciphertext, char[] password)
      throws CryptorException {
    Validate.notNull(ciphertext, "Ciphertext cannot be null.");

    try {
      AES256Ciphertext aesCiphertext = new AES256Ciphertext(ciphertext);
      SecretKey decryptionKey = keyForPassword(password,
          aesCiphertext.getEncryptionSalt());
      SecretKey hmacKey = keyForPassword(password, aesCiphertext.getHmacSalt());

      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(hmacKey);
      byte[] hmacValue = mac.doFinal(aesCiphertext.getCiphertext());

      if (!Arrays.equals(hmacValue, aesCiphertext.getHmac())) {
        throw new InvalidHMACException("Incorrect HMAC value.");
      }

      Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(
          aesCiphertext.getIv()));

      return cipher.doFinal(aesCiphertext.getCiphertext());

    } catch (InvalidDataException e) {
      throw new CryptorException("Unable to parse ciphertext.", e);
    } catch (GeneralSecurityException e) {
      throw new CryptorException("Failed to decrypt message.", e);
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

      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(hmacKey);
      byte[] hmac = mac.doFinal(ciphertext);

      AES256Ciphertext output = new AES256Ciphertext(encryptionSalt, hmacSalt,
          iv, ciphertext, hmac);
      return output.getRawData();

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
    Validate.isTrue(length > 0, "Length must be positive.");

    byte[] result = new byte[length];
    SECURE_RANDOM.nextBytes(result);
    return result;
  }

  @Override
  public int getVersionNumber() {
    return VERSION;
  }
}
