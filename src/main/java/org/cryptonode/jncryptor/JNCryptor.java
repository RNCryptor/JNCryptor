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

import javax.crypto.SecretKey;

/**
 * A {@link JNCryptor} encrypts and decrypts data in a proprietary format
 * originally devised by Rob Napier. Use the
 * {@link JNCryptorFactory#getCryptor()} method to retrieve a concrete
 * implementation.
 * <p>
 * A {@code JNCryptor} must be threadsafe, as a single instance will be returned
 * from the {@code JNCryptorFactory} and potentially shared between threads.
 * <p>
 * See <a
 * href="https://github.com/rnapier/RNCryptor">https://github.com/rnapier/
 * RNCryptor</a> for details on the original implementation in objective-c
 */
public interface JNCryptor {

  /**
   * Generates a key given a password and salt using a PBKDF.
   * 
   * @param password
   *          password to use for PBKDF, can be <code>null</code> in which case
   *          the behaviour is identical to passing an empty char array
   * @param salt
   *          salt for password, cannot be <code>null</code>
   * @return the key
   */
  SecretKey keyForPassword(char[] password, byte[] salt)
      throws CryptorException;

  /**
   * Decrypts data with the supplied password.
   * 
   * @param ciphertext
   *          data to decrypt. Must be in the format described at <a
   *          href="https://github.com/rnapier/RNCryptor/wiki/Data-Format"
   *          >https://github.com/rnapier/RNCryptor/wiki/Data-Format</a>
   * @param password
   *          password to use for the decryption. A <code>null</code> value or
   *          an empty char array are considered equal (and are both valid
   *          values).
   * @return the plain text
   * @throws InvalidHMACException
   */
  byte[] decryptData(byte[] ciphertext, char[] password)
      throws CryptorException, InvalidHMACException;

  /**
   * Decrypts data with the supplied keys.
   * 
   * @param ciphertext
   *          data to decrypt. Must be in the format described at <a
   *          href="https://github.com/rnapier/RNCryptor/wiki/Data-Format"
   *          >https://github.com/rnapier/RNCryptor/wiki/Data-Format</a>
   * @param decryptionKey
   *          the key to decrypt with
   * @param hmacKey
   *          the key to verify the HMAC with
   * @return the plain text
   * @throws InvalidHMACException
   */
  byte[] decryptData(byte[] ciphertext, SecretKey decryptionKey,
      SecretKey hmacKey) throws CryptorException, InvalidHMACException;

  /**
   * Encrypts data with the supplied password.
   * 
   * @param plaintext
   *          the data to encrypt
   * @param password
   *          password to use for the encryption. A <code>null</code> value or
   *          an empty char array are considered equal (and are both valid
   *          values).
   * @return the ciphertext, in the format described at <a
   *         href="https://github.com/rnapier/RNCryptor/wiki/Data-Format"
   *         >https://github.com/rnapier/RNCryptor/wiki/Data-Format</a>
   */
  byte[] encryptData(byte[] plaintext, char[] password) throws CryptorException;

  /**
   * Encrypts data with the supplied keys.
   * 
   * @param plaintext
   *          the data to encrypt
   * @param encryptionKey
   *          key to use for encryption
   * @param hmacKey
   *          key to use for computing the HMAC
   * @return the ciphertext, in the format described at <a
   *         href="https://github.com/rnapier/RNCryptor/wiki/Data-Format"
   *         >https://github.com/rnapier/RNCryptor/wiki/Data-Format</a>
   */
  byte[] encryptData(byte[] plaintext, SecretKey encryptionKey,
      SecretKey hmacKey) throws CryptorException;

  /**
   * Returns the version number of this {@code JNCryptor}.
   * 
   * @return the version number
   */
  int getVersionNumber();

  /**
   * Changes the number of iterations used by this {@code JNCryptor}.
   * 
   * @param iterations
   * @since 0.4
   */
  void setPBKDFIterations(int iterations);
}
