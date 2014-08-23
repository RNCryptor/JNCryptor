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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Writes RNCryptor-format (version 3) data in a stream fashion. The stream must
 * be closed to finish writing the data and output the HMAC value.
 * 
 * @since 1.1.0
 */
public class AES256JNCryptorOutputStream extends OutputStream {

  private CipherOutputStream cipherStream;
  private MacOutputStream macOutputStream;
  private boolean writtenHeader;
  private final boolean passwordBased;
  private byte[] encryptionSalt;
  private byte[] iv;
  private byte[] hmacSalt;

  /**
   * Creates an output stream for key-encrypted data.
   *
   * @param out
   *          the {@code OutputStream} to write the JNCryptor data to
   * @param encryptionKey
   *          the key to encrypt with
   * @param hmacKey
   *          the key to calculate the HMAC with
   */
  public AES256JNCryptorOutputStream(OutputStream out, SecretKey encryptionKey,
      SecretKey hmacKey) throws CryptorException {

    Validate.notNull(out, "Output stream cannot be null.");
    Validate.notNull(encryptionKey, "Encryption key cannot be null.");
    Validate.notNull(hmacKey, "HMAC key cannot be null.");

    byte[] iv = AES256JNCryptor
        .getSecureRandomData(AES256Ciphertext.AES_BLOCK_SIZE);

    passwordBased = false;
    createStreams(encryptionKey, hmacKey, iv, out);
  }

  /**
   * Creates an output stream for password-encrypted data, using a specific
   * number of PBKDF iterations.
   *
   * @param out
   *          the {@code OutputStream} to write the JNCryptor data to
   * @param password
   *          the password
   * @param iterations
   *          the number of PBKDF iterations to perform
   */
  public AES256JNCryptorOutputStream(OutputStream out, char[] password,
      int iterations) throws CryptorException {

    Validate.notNull(out, "Output stream cannot be null.");
    Validate.notNull(password, "Password cannot be null.");
    Validate.isTrue(password.length > 0, "Password cannot be empty.");
    Validate.isTrue(iterations > 0, "Iterations must be greater than zero.");

    AES256JNCryptor cryptor = new AES256JNCryptor(iterations);

    encryptionSalt = AES256JNCryptor
        .getSecureRandomData(AES256JNCryptor.SALT_LENGTH);
    SecretKey encryptionKey = cryptor.keyForPassword(password, encryptionSalt);

    hmacSalt = AES256JNCryptor.getSecureRandomData(AES256JNCryptor.SALT_LENGTH);
    SecretKey hmacKey = cryptor.keyForPassword(password, hmacSalt);

    iv = AES256JNCryptor.getSecureRandomData(AES256Ciphertext.AES_BLOCK_SIZE);

    passwordBased = true;
    createStreams(encryptionKey, hmacKey, iv, out);
  }

  /**
   * Creates an output stream for password-encrypted data.
   *
   * @param out
   *          the {@code OutputStream} to write the JNCryptor data to
   * @param password
   *          the password
   */
  public AES256JNCryptorOutputStream(OutputStream out, char[] password)
      throws CryptorException {
    this(out, password, AES256JNCryptor.PBKDF_DEFAULT_ITERATIONS);
  }

  /**
   * Creates the cipher and MAC streams required,
   * 
   * @param encryptionKey
   *          the encryption key
   * @param hmacKey
   *          the HMAC key
   * @param iv
   *          the IV
   * @param out
   *          the output stream we are wrapping
   * @throws CryptorException
   */
  private void createStreams(SecretKey encryptionKey, SecretKey hmacKey,
      byte[] iv, OutputStream out) throws CryptorException {

    this.iv = iv;

    try {
      Cipher cipher = Cipher.getInstance(AES256JNCryptor.AES_CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(iv));

      try {
        Mac mac = Mac.getInstance(AES256JNCryptor.HMAC_ALGORITHM);
        mac.init(hmacKey);

        macOutputStream = new MacOutputStream(out, mac);
        cipherStream = new CipherOutputStream(macOutputStream, cipher);

      } catch (GeneralSecurityException e) {
        throw new CryptorException("Failed to initialize HMac", e);
      }

    } catch (GeneralSecurityException e) {
      throw new CryptorException("Failed to initialize AES cipher", e);
    }
  }

  /**
   * Writes the header data to the output stream.
   * 
   * @throws IOException
   */
  private void writeHeader() throws IOException {
    /* Write out the header */
    if (passwordBased) {
      macOutputStream.write(AES256JNCryptor.VERSION);
      macOutputStream.write(AES256Ciphertext.FLAG_PASSWORD);
      macOutputStream.write(encryptionSalt);
      macOutputStream.write(hmacSalt);
      macOutputStream.write(iv);
    } else {
      macOutputStream.write(AES256JNCryptor.VERSION);
      macOutputStream.write(0);
      macOutputStream.write(iv);
    }
  }

  /**
   * Writes one byte to the encrypted output stream.
   * 
   * @param b
   *          the byte to write
   * @throws IOException
   *           if an I/O error occurs
   */
  @Override
  public void write(int b) throws IOException {
    if (!writtenHeader) {
      writeHeader();
      writtenHeader = true;
    }
    cipherStream.write(b);
  }

  /**
   * Writes bytes to the encrypted output stream.
   * 
   * @param b
   *          a buffer of bytes to write
   * @param off
   *          the offset into the buffer
   * @param len
   *          the number of bytes to write (starting from the offset)
   * @throws IOException
   *           if an I/O error occurs
   */
  @Override
  public void write(byte[] b, int off, int len) throws IOException {
    if (!writtenHeader) {
      writeHeader();
      writtenHeader = true;
    }
    cipherStream.write(b, off, len);
  }

  /**
   * Closes the stream. This causes the HMAC calculation to be concluded and
   * written to the output.
   * 
   * @throws IOException
   *           if an I/O error occurs
   */
  @Override
  public void close() throws IOException {
    cipherStream.close();
  }

  /**
   * An output stream to update a Mac object with all bytes passed through, then
   * write the Mac data to the stream upon close to complete the RNCryptor file
   * format.
   */
  private static class MacOutputStream extends FilterOutputStream {
    private final Mac mac;

    MacOutputStream(OutputStream out, Mac mac) {
      super(out);
      this.mac = mac;
    }

    @Override
    public void write(int b) throws IOException {
      mac.update((byte) b);
      out.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
      mac.update(b, off, len);
      out.write(b, off, len);
    }

    @Override
    public void close() throws IOException {
      byte[] macData = mac.doFinal();
      out.write(macData);
      out.flush();
      out.close();
    }
  }
}
