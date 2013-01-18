package jncryptor.cryptography;

import javax.crypto.SecretKey;

/**
 * An {@link JNCryptor} encrypts and decrypts data in a proprietary format
 * originally devised by Rob Napier. Use the
 * {@link JNCryptorFactory#getCryptor()} method to retrieve a concrete
 * implementation.
 * <p>
 * An {@code JNCryptor} must be threadsafe, as a single instance will be
 * returned from the {@code JNCryptorFactory} and potentially shared between
 * threads.
 * 
 * @see https://github.com/rnapier/RNCryptor for details on the original
 *      implementation in objective-c
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
   *          data to decrypt. Must be in the format described at
   *          https://github.com/rnapier/RNCryptor/wiki/Data-Format
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
   * Encrypts data with the supplied password.
   * 
   * @param plaintext
   *          the data to encrypt
   * @param password
   *          password to use for the encryption. A <code>null</code> value or
   *          an empty char array are considered equal (and are both valid
   *          values).
   * @return the ciphertext, in the format described at
   *         https://github.com/rnapier/RNCryptor/wiki/Data-Format
   */
  byte[] encryptData(byte[] plaintext, char[] password) throws CryptorException;

  /**
   * Returns the version number of this {@code RNCryptor}.
   * 
   * @return the version number
   */
  int getVersionNumber();
}
