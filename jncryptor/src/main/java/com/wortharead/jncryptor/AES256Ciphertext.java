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

import org.apache.commons.lang3.Validate;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/**
 * Class for parsing and producing formatted ciphertext.
 */
class AES256Ciphertext {

  // Values are default protection to share with unit
  // tests
  static final int FLAG_PASSWORD = 0x01;
  static final int ENCRYPTION_SALT_LENGTH = 8;
  static final int HMAC_SALT_LENGTH = 8;
  static final int AES_BLOCK_SIZE = 16;
  static final int HMAC_SIZE = 32;
  static final int EXPECTED_VERSION = 1;
  static final int HEADER_SIZE = 2;

  static final int MINIMUM_LENGTH_WITH_PASSWORD = HEADER_SIZE
      + ENCRYPTION_SALT_LENGTH + HMAC_SALT_LENGTH + AES_BLOCK_SIZE + HMAC_SIZE;

  static final int MINIMUM_LENGTH_WITHOUT_PASSWORD = HEADER_SIZE
      + AES_BLOCK_SIZE + HMAC_SIZE;

  private final int version;
  private final byte options;
  private final byte[] encryptionSalt;
  private final byte[] hmacSalt;
  private final byte[] iv;
  private final byte[] ciphertext;
  private final byte[] hmac;
  private final boolean isPasswordBased;

  /**
   * Parses binary data to create an {@code AES256Ciphertext}.
   * 
   * @param data
   *          the data to parse
   * @throws InvalidDataException
   *           if the data is not valid
   */
  AES256Ciphertext(byte[] data) throws InvalidDataException {
    Validate.notNull(data, "Data cannot be null.");

    // Need the header to be able to determine the length
    if (data.length < HEADER_SIZE) {
      throw new InvalidDataException("Not enough data to read header.");
    }

    int index = 0;
    version = data[index++];

    if (version != EXPECTED_VERSION) {
      throw new InvalidDataException(String.format(
          "Expected version %d but found %d.", EXPECTED_VERSION, version));
    }

    options = data[index++];

    // Test for any invalid flags
    if (options != 0x00 && options != FLAG_PASSWORD) {
      throw new InvalidDataException("Unrecognised bit in the options byte.");
    }

    // If the password bit is set, we can expect salt values
    isPasswordBased = ((options & FLAG_PASSWORD) == FLAG_PASSWORD);

    final int minimumLength = (isPasswordBased) ? MINIMUM_LENGTH_WITH_PASSWORD
        : MINIMUM_LENGTH_WITHOUT_PASSWORD;

    if (data.length < minimumLength) {
      throw new InvalidDataException(String.format(
          "Data must be a minimum length of %d bytes, but found %d bytes.",
          minimumLength, data.length));
    }

    final int ciphertextLength = data.length - minimumLength;

    if (isPasswordBased) {
      encryptionSalt = new byte[ENCRYPTION_SALT_LENGTH];
      System.arraycopy(data, index, encryptionSalt, 0, encryptionSalt.length);
      index += encryptionSalt.length;

      hmacSalt = new byte[HMAC_SALT_LENGTH];
      System.arraycopy(data, index, hmacSalt, 0, hmacSalt.length);
      index += hmacSalt.length;
    } else {
      encryptionSalt = null;
      hmacSalt = null;
    }

    iv = new byte[AES_BLOCK_SIZE];
    System.arraycopy(data, index, iv, 0, iv.length);
    index += iv.length;

    ciphertext = new byte[ciphertextLength];
    System.arraycopy(data, index, ciphertext, 0, ciphertextLength);
    index += ciphertextLength;

    hmac = new byte[HMAC_SIZE];
    System.arraycopy(data, index, hmac, 0, hmac.length);
  }

  /**
   * Constructs a {@code CryptorData} from its constituent parts. An
   * {@code IllegalArgumentException} is thrown if any of the parameters are of
   * the wrong length or invalid.
   * <p>
   * This constructor is used if the data was encrypted with a password.
   * 
   * @param encryptionSalt
   *          the encryption salt
   * @param hmacSalt
   *          the HMAC salt
   * @param iv
   *          the initialisation value
   * @param ciphertext
   *          the encrypted data
   * @param hmac
   *          the HMAC value
   */
  AES256Ciphertext(byte[] encryptionSalt, byte[] hmacSalt, byte[] iv,
      byte[] ciphertext, byte[] hmac) {

    validateLength(encryptionSalt, "encryption salt", ENCRYPTION_SALT_LENGTH);
    validateLength(hmacSalt, "HMAC salt", HMAC_SALT_LENGTH);
    validateLength(iv, "IV", AES_BLOCK_SIZE);
    validateLength(hmac, "HMAC", HMAC_SIZE);

    this.version = EXPECTED_VERSION;
    this.options = FLAG_PASSWORD;
    this.encryptionSalt = encryptionSalt;
    this.hmacSalt = hmacSalt;
    this.iv = iv;
    this.ciphertext = ciphertext;
    this.hmac = hmac;
    this.isPasswordBased = true;
  }

  /**
   * Constructs a {@code CryptorData} from its constituent parts. An
   * {@code IllegalArgumentException} is thrown if any of the parameters are of
   * the wrong length or invalid.
   * <p>
   * This constructor is used if the data was encrypted with a key.
   * 
   * @param iv
   *          the initialisation value
   * @param ciphertext
   *          the encrypted data
   * @param hmac
   *          the HMAC value
   */
  AES256Ciphertext(byte[] iv, byte[] ciphertext, byte[] hmac) {

    validateLength(iv, "IV", AES_BLOCK_SIZE);
    validateLength(hmac, "HMAC", HMAC_SIZE);

    this.version = EXPECTED_VERSION;
    this.options = 0;
    this.iv = iv;
    this.ciphertext = ciphertext;
    this.hmac = hmac;

    this.encryptionSalt = null;
    this.hmacSalt = null;
    this.isPasswordBased = false;
  }

  /**
   * Checks the length of a byte array.
   * 
   * @param data
   *          the data to check
   * @param dataName
   *          the name of the field (to include in the exception)
   * @param expectedLength
   *          the length the data should be
   * @throws IllegalArgumentException
   *           if the data is not of the correct length
   */
  private static void validateLength(byte[] data, String dataName,
      int expectedLength) throws IllegalArgumentException {
    if (data.length != expectedLength) {
      throw new IllegalArgumentException(String.format(
          "Invalid %s length. Expected %d bytes but found %d.", dataName,
          expectedLength, data.length));
    }
  }

  /**
   * Returns the ciphertext, packaged as a byte array.
   * 
   * @return the byte array
   */
  byte[] getRawData() {

    // Header: [Version | Options]
    byte[] header = new byte[] { EXPECTED_VERSION, 0 };

    if (isPasswordBased) {
      header[1] |= FLAG_PASSWORD;
    }

    // Pack result
    final int dataSize;

    if (isPasswordBased) {
      dataSize = header.length + encryptionSalt.length + hmacSalt.length
          + iv.length + ciphertext.length + hmac.length;
    } else {
      dataSize = header.length + iv.length + ciphertext.length + hmac.length;
    }

    byte[] result = new byte[dataSize];

    System.arraycopy(header, 0, result, 0, header.length);

    if (isPasswordBased) {
      System.arraycopy(encryptionSalt, 0, result, header.length,
          encryptionSalt.length);
      System.arraycopy(hmacSalt, 0, result, header.length
          + encryptionSalt.length, hmacSalt.length);
    }

    System.arraycopy(iv, 0, result, header.length + encryptionSalt.length
        + hmacSalt.length, iv.length);
    System.arraycopy(ciphertext, 0, result, header.length
        + encryptionSalt.length + hmacSalt.length + iv.length,
        ciphertext.length);
    System.arraycopy(hmac, 0, result, header.length + encryptionSalt.length
        + hmacSalt.length + iv.length + ciphertext.length, hmac.length);

    return result;
  }

  /**
   * @return the version
   */
  int getVersion() {
    return version;
  }

  /**
   * @return the options
   */
  byte getOptions() {
    return options;
  }

  /**
   * @return the encryptionSalt
   */
  byte[] getEncryptionSalt() {
    return encryptionSalt;
  }

  /**
   * @return the hmacSalt
   */
  byte[] getHmacSalt() {
    return hmacSalt;
  }

  /**
   * @return the iv
   */
  byte[] getIv() {
    return iv;
  }

  /**
   * @return the ciphertext
   */
  byte[] getCiphertext() {
    return ciphertext;
  }

  /**
   * @return the hmac
   */
  byte[] getHmac() {
    return hmac;
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this,
        ToStringStyle.SHORT_PREFIX_STYLE);
  }

  @Override
  public boolean equals(Object obj) {
    return EqualsBuilder.reflectionEquals(this, obj, false);
  }

  /**
   * Indicates if the ciphertext was created using a password. If so, then the
   * salt values will be present in the ciphertext.
   * 
   * @return <code>true</code> if the ciphertext was created with a password
   *         (not a key), <code>false</code> otherwise
   */
  public boolean isPasswordBased() {
    return isPasswordBased;
  }
}
