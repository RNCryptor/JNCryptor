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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This {@link JNCryptor} instance produces data in version 3 format. It can
 * read data in any format since version 2.
 * <p>
 * 
 * <pre>
 * | version | options | encryption salt | HMAC salt |   IV   | ... ciphertext ... |     HMAC    |
 * |    0    |    1    |       2->9      |   10->17  | 18->33 | <-      ...     -> | (n-32) -> n |
 * </pre>
 * 
 * <ul>
 * <li><b>version</b> (1 byte): Data format version.</li>
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
 * iteration count can be changed using the {@link #setPBKDFIterations(int)}
 * method. The HMAC key is derived in a similar fashion, using its own random
 * eight-byte HMAC salt. Both salt values are stored in the ciphertext output
 * (as shown above).
 * 
 * <p>
 * The ciphertext is AES-256-CBC encrypted, using a randomly generated IV and
 * the encryption key (described above), with PKCS&nbsp;#5 padding.
 * <p>
 * The HMAC is calculated across all the data (except the HMAC itself, of
 * course), generated using the HMAC key described above and the SHA-256 PRF.
 * <p>
 * <p>
 * This class is thread-safe. Multiple threads may share one instance of this
 * class, or each thread may have its own instance.
 * </p>
 * See <a
 * href="https://github.com/rnapier/RNCryptor/wiki/Data-Format">https://github
 * .com/rnapier/RNCryptor/wiki/Data-Format</a>, from which most of the
 * information above was shamelessly copied.
 * 
 * @since 0.5
 */
public class AES256JNCryptor implements JNCryptor {

  /**
   * AES encryption/decryption algorithm.
   */
  static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

  /**
   * HMAC algorithm
   */
  static final String HMAC_ALGORITHM = "HmacSHA256";
  
  /**
   * AES algorithm name.
   */
  static final String AES_NAME = "AES";
  
  /**
   * The key derivation algorith name
   */
  static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA1";
  
  /**
   * The default number of PBKDF2 iterations.
   */
  static final int PBKDF_DEFAULT_ITERATIONS = 10000;
  
  /**
   * The data format version number.
   */
  static final int VERSION = 3;
  
  /**
   * The size of an AES key (useful constant).
   */
  static final int AES_256_KEY_SIZE = 256 / 8;
  
  /**
   * AES block size in bytes.
   */
  static final int AES_BLOCK_SIZE = 16;

  /**
   * Size of the salt (in bytes)
   */
  static final int SALT_LENGTH = 8;

  // SecureRandom is threadsafe
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  // Access to this variable must be synchronized
  private int iterations = PBKDF_DEFAULT_ITERATIONS;

  /**
   * Creates a new {@code AES256JNCryptor} instance. Uses the default number of
   * PBKDF iterations.
   */
  public AES256JNCryptor() {
  }

  /**
   * Creates a new {@code AES256JNCryptor} instance that uses a specific number
   * of PBKDF iterations.
   * 
   * @param iterations
   *          the number of PBKDF iterations to perform
   */
  public AES256JNCryptor(int iterations) {
    Validate.isTrue(iterations > 0, "Iteration value must be positive.");

    this.iterations = iterations;
  }

  @Override
  public SecretKey keyForPassword(char[] password, byte[] salt)
      throws CryptorException {

    Validate.notNull(salt, "Salt value cannot be null.");
    Validate.isTrue(salt.length == SALT_LENGTH, "Salt value must be %d bytes.",
        SALT_LENGTH);
    Validate.notNull(password, "Password cannot be null.");
    Validate.isTrue(password.length > 0, "Password cannot be empty.");

    try {
      SecretKeyFactory factory = SecretKeyFactory
          .getInstance(KEY_DERIVATION_ALGORITHM);
      SecretKey tmp = factory.generateSecret(new PBEKeySpec(password, salt,
          getPBKDFIterations(), AES_256_KEY_SIZE * 8));
      return new SecretKeySpec(tmp.getEncoded(), AES_NAME);
    } catch (GeneralSecurityException e) {
      throw new CryptorException(String.format(
          "Failed to generate key from password using %s.",
          KEY_DERIVATION_ALGORITHM), e);
    }
  }

  @Override
  public synchronized int getPBKDFIterations() {
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
  private byte[] decryptV2Data(AES256v2Ciphertext aesCiphertext,
      SecretKey decryptionKey, SecretKey hmacKey) throws CryptorException {

    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(hmacKey);
      byte[] hmacValue = mac.doFinal(aesCiphertext.getDataToHMAC());

      if (!arraysEqual(hmacValue, aesCiphertext.getHmac())) {
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
  private byte[] decryptV3Data(AES256v3Ciphertext aesCiphertext,
      SecretKey decryptionKey, SecretKey hmacKey) throws CryptorException {

    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(hmacKey);
      byte[] hmacValue = mac.doFinal(aesCiphertext.getDataToHMAC());

      if (!arraysEqual(hmacValue, aesCiphertext.getHmac())) {
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
    Validate.notNull(password, "Password cannot be null.");
    Validate.isTrue(password.length > 0, "Password cannot be empty.");

    // I don't like the magic numbers here, but can't think of a pleasant way
    // to solve this
    int version = readVersionNumber(ciphertext);
    switch (version) {
    case 2:
      return decryptV2Data(ciphertext, password);

    case 3:
      return decryptV3Data(ciphertext, password);

    default:
      throw new CryptorException(String.format(
          "Unrecognised version number: %d.", version));
    }

  }

  private byte[] decryptV2Data(byte[] ciphertext, char[] password)
      throws CryptorException {
    try {
      AES256v2Ciphertext aesCiphertext = new AES256v2Ciphertext(ciphertext);

      if (!aesCiphertext.isPasswordBased()) {
        throw new IllegalArgumentException(
            "Ciphertext was not encrypted with a password.");
      }

      SecretKey decryptionKey = keyForPassword(password,
          aesCiphertext.getEncryptionSalt());
      SecretKey hmacKey = keyForPassword(password, aesCiphertext.getHmacSalt());

      return decryptV2Data(aesCiphertext, decryptionKey, hmacKey);
    } catch (InvalidDataException e) {
      throw new CryptorException("Unable to parse ciphertext.", e);
    }
  }

  private byte[] decryptV3Data(byte[] ciphertext, char[] password)
      throws CryptorException {
    try {
      AES256v3Ciphertext aesCiphertext = new AES256v3Ciphertext(ciphertext);

      if (!aesCiphertext.isPasswordBased()) {
        throw new IllegalArgumentException(
            "Ciphertext was not encrypted with a password.");
      }

      SecretKey decryptionKey = keyForPassword(password,
          aesCiphertext.getEncryptionSalt());
      SecretKey hmacKey = keyForPassword(password, aesCiphertext.getHmacSalt());

      return decryptV3Data(aesCiphertext, decryptionKey, hmacKey);
    } catch (InvalidDataException e) {
      throw new CryptorException("Unable to parse ciphertext.", e);
    }
  }

  @Override
  public byte[] encryptData(byte[] plaintext, char[] password, byte[] encryptionSalt,
      byte[] hmacSalt, byte[] iv) throws CryptorException {

    Validate.notNull(plaintext, "Plaintext cannot be null.");

    Validate.notNull(password, "Password cannot be null.");
    Validate.isTrue(password.length > 0, "Password cannot be empty.");
    
    Validate.isCorrectLength(encryptionSalt, SALT_LENGTH, "Encryption salt");
    Validate.isCorrectLength(hmacSalt, SALT_LENGTH, "HMAC salt");
    Validate.isCorrectLength(iv, AES_BLOCK_SIZE, "IV");
    
    SecretKey encryptionKey = keyForPassword(password, encryptionSalt);
    SecretKey hmacKey = keyForPassword(password, hmacSalt);
    
    return encryptData(plaintext,
        new PasswordKey(encryptionKey, encryptionSalt), new PasswordKey(
            hmacKey, hmacSalt), iv);
  }

  @Override
  public byte[] encryptData(byte[] plaintext, char[] password)
      throws CryptorException {
    Validate.notNull(plaintext, "Plaintext cannot be null.");
    Validate.notNull(password, "Password cannot be null.");
    Validate.isTrue(password.length > 0, "Password cannot be empty.");

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
  static byte[] getSecureRandomData(int length) {
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

    try {
      int version = readVersionNumber(ciphertext);

      switch (version) {
      case 2:
        return decryptV2Data(new AES256v2Ciphertext(ciphertext), decryptionKey,
            hmacKey);
      case 3:
        return decryptV3Data(new AES256v3Ciphertext(ciphertext), decryptionKey,
            hmacKey);
      default:
        throw new CryptorException(String.format(
            "Unrecognised version number: %d.", version));
      }

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

      AES256v3Ciphertext output = new AES256v3Ciphertext(iv, ciphertext);

      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(hmacKey);
      byte[] hmac = mac.doFinal(output.getDataToHMAC());
      output.setHmac(hmac);
      return output.getRawData();

    } catch (GeneralSecurityException e) {
      throw new CryptorException("Failed to generate ciphertext.", e);
    }
  }

  private static int readVersionNumber(byte[] data) {
    Validate.isTrue(data.length > 0,
        "Data must be at least one byte long to read version number.");

    return data[0];
  }
  
  /**
   * Compares arrays for equality in constant time. This avoids
   * certain types of timing attacks.
   * 
   * @param array1 the first array
   * @param array2 the second array
   * @return whether the arrays match
   */
  static boolean arraysEqual(byte[] array1, byte[] array2) {
    if (array1.length != array2.length) {
      return false;
    }
    
    boolean isEqual = true;
    for (int i = 0; i < array1.length; i++) {
      if (array1[i] != array2[i]) {
        isEqual = false;
      }
    }
    return isEqual;
  }

  @Override
  public PasswordKey getPasswordKey(char[] password) throws CryptorException {
    Validate.notNull(password, "Password cannot be null.");
    Validate.isTrue(password.length > 0, "Password cannot be empty.");    
    
    byte[] salt = new byte[SALT_LENGTH];
    SECURE_RANDOM.nextBytes(salt);
    SecretKey secretKey = keyForPassword(password, salt);
    return new PasswordKey(secretKey, salt);
  }
  
  byte[] encryptData(byte[] plaintext, PasswordKey encryptionKey, PasswordKey hmacKey, byte[] iv) throws CryptorException {
    try {
      Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, encryptionKey.getKey(), new IvParameterSpec(iv));
      byte[] ciphertext = cipher.doFinal(plaintext);

      AES256v3Ciphertext output = new AES256v3Ciphertext(encryptionKey.getSalt(),
          hmacKey.getSalt(), iv, ciphertext);

      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(hmacKey.getKey());
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
  public byte[] encryptData(byte[] plaintext, PasswordKey encryptionKey,
      PasswordKey hmacKey) throws CryptorException {
    byte[] iv = new byte[AES_BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    return encryptData(plaintext, encryptionKey, hmacKey, iv);
  }
}
