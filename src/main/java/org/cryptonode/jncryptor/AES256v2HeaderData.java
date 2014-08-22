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

class AES256v2HeaderData {
  private static final int SIZE_WITH_PASSWORD = AES256v3Ciphertext.HEADER_SIZE
      + AES256v3Ciphertext.ENCRYPTION_SALT_LENGTH
      + AES256v3Ciphertext.HMAC_SALT_LENGTH + AES256v3Ciphertext.AES_BLOCK_SIZE;

  private static final int SIZE_WITHOUT_PASSWORD = AES256v3Ciphertext.HEADER_SIZE
      + AES256v3Ciphertext.AES_BLOCK_SIZE;

  private final byte version;
  private final byte options;
  private final byte[] encryptionSalt;
  private final byte[] hmacSalt;
  private final byte[] iv;
  private final boolean isPasswordBased;

  /**
   * Parses the header data.
   * 
   * @throws InvalidDataException
   * 
   */
  AES256v2HeaderData(byte[] data) throws InvalidDataException {
    Validate.notNull(data, "Data cannot be null.");

    // Need the header to be able to determine the length
    if (data.length < AES256v3Ciphertext.HEADER_SIZE) {
      throw new InvalidDataException("Not enough data to read header.");
    }

    int index = 0;
    version = data[index++];

    if (version != AES256v3Ciphertext.EXPECTED_VERSION) {
      throw new InvalidDataException(String.format(
          "Expected version %d but found %d.",
          AES256v3Ciphertext.EXPECTED_VERSION, version));
    }

    options = data[index++];

    // Test for any invalid flags
    if (options != 0x00 && options != AES256v3Ciphertext.FLAG_PASSWORD) {
      throw new InvalidDataException("Unrecognised bit in the options byte.");
    }

    // If the password bit is set, we can expect salt values
    isPasswordBased = ((options & AES256v3Ciphertext.FLAG_PASSWORD) == AES256v3Ciphertext.FLAG_PASSWORD);

    final int minimumLength = (isPasswordBased) ? SIZE_WITH_PASSWORD
        : SIZE_WITHOUT_PASSWORD;

    if (data.length < minimumLength) {
      throw new InvalidDataException(String.format(
          "Data must be a minimum length of %d bytes, but found %d bytes.",
          minimumLength, data.length));
    }

    if (isPasswordBased) {
      encryptionSalt = new byte[AES256v3Ciphertext.ENCRYPTION_SALT_LENGTH];
      System.arraycopy(data, index, encryptionSalt, 0, encryptionSalt.length);
      index += encryptionSalt.length;

      hmacSalt = new byte[AES256v3Ciphertext.HMAC_SALT_LENGTH];
      System.arraycopy(data, index, hmacSalt, 0, hmacSalt.length);
      index += hmacSalt.length;
    } else {
      encryptionSalt = null;
      hmacSalt = null;
    }

    iv = new byte[AES256v3Ciphertext.AES_BLOCK_SIZE];
    System.arraycopy(data, index, iv, 0, iv.length);
    index += iv.length;
  }

  /**
   * Gets the size of the header for password-protected data.
   * 
   * @return the byte length
   */
  static int getSizeWithPassword() {
    return SIZE_WITH_PASSWORD;
  }

  /**
   * Gets the size of the header for key-protected data.
   * 
   * @return the byte length
   */
  static int getSizeWithoutPassword() {
    return SIZE_WITHOUT_PASSWORD;
  }

  /**
   * Gets the version byte.
   * 
   * @return the version byte
   */
  byte getVersion() {
    return version;
  }

  /**
   * Getes the options byte.
   * 
   * @return the options byte
   */
  byte getOptions() {
    return options;
  }

  /**
   * Returns the encryption salt. Will be <code>null</code> if the header is for
   * key-protected data.
   * 
   * @return the encryption salt, or <code>null</code>
   */
  byte[] getEncryptionSalt() {
    return encryptionSalt;
  }

  /**
   * Returns the HMAC salt. Will be <code>null</code> if the header is for
   * key-protected data.
   * 
   * @return the HMAC salt, or <code>null</code>
   */
  byte[] getHmacSalt() {
    return hmacSalt;
  }

  /**
   * The IV value.
   * 
   * @return the iv
   */
  byte[] getIv() {
    return iv;
  }

  /**
   * Indicates if the header is for password-protected data or key-protected
   * data. In the former case, the encryption and HMAC salt values will be
   * included.
   * 
   * @return <code>true</code> if the header is for password-protected data,
   *         <code>false</code> otherwise
   */
  boolean isPasswordBased() {
    return isPasswordBased;
  }

}