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

import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Reads RNCryptor-format data in a stream fashion. This class only
 * supports the v3 data format. The entire stream must be read in order
 * to trigger the validation of the HMAC value.
 * 
 * @since 1.1.0
 */
public class AES256JNCryptorInputStream extends InputStream {

  private static final int END_OF_STREAM = -1;
  private final boolean isPasswordEncrypted;
  private final InputStream in;

  private char[] password;
  private SecretKey decryptionKey;
  private SecretKey hmacKey;
  private boolean endOfStreamHandled = false;

  private PushbackInputStream pushbackInputStream;
  private TrailerInputStream trailerIn;
  private Mac mac;

  /**
   * Creates an input stream for password-encrypted data.
   * 
   * @param in
   *          the {@code InputStream} to read
   * @param password
   *          the password
   */
  public AES256JNCryptorInputStream(InputStream in, char[] password) {
    isPasswordEncrypted = true;
    this.password = password;
    this.in = in;
  }

  /**
   * Creates an input stream for key-encrypted data.
   * 
   * @param in
   *          the {@code InputStream} to read
   * @param decryptionKey
   *          the key to decrypt with
   * @param hmacKey
   *          the key to calculate the HMAC with
   */
  public AES256JNCryptorInputStream(InputStream in, SecretKey decryptionKey,
      SecretKey hmacKey) {
    isPasswordEncrypted = false;
    this.decryptionKey = decryptionKey;
    this.hmacKey = hmacKey;
    this.in = in;
  }

  /**
   * Mark and reset methods are not supported in this input stream.
   * 
   * @return <code>false</code>
   */
  @Override
  public boolean markSupported() {
    return false;
  }

  /**
   * Reads the header data, derives keys if necessary and creates the input
   * streams.
   * 
   * @throws IOException
   *           if an error occurs
   * @throws EOFException
   *           if we run out of data before reading the header
   */
  private void initializeStream() throws IOException {
    int headerDataSize;
    if (isPasswordEncrypted) {
      headerDataSize = AES256v3Ciphertext.HEADER_SIZE
          + AES256v3Ciphertext.ENCRYPTION_SALT_LENGTH
          + AES256v3Ciphertext.HMAC_SALT_LENGTH
          + AES256v3Ciphertext.AES_BLOCK_SIZE;
    } else {
      headerDataSize = AES256v3Ciphertext.HEADER_SIZE
          + AES256v3Ciphertext.AES_BLOCK_SIZE;
    }

    byte[] headerData = new byte[headerDataSize];
    StreamUtils.readAllBytesOrFail(in, headerData); // throws EOF if insufficient data

    int offset = 0;
    byte version = headerData[offset++];

    if (version != AES256v3Ciphertext.EXPECTED_VERSION) {
      throw new IOException(String.format("Expected version %d but found %d.",
          AES256v3Ciphertext.EXPECTED_VERSION, version));
    }

    byte options = headerData[offset++];

    if (isPasswordEncrypted) {
      if (options != AES256v3Ciphertext.FLAG_PASSWORD) {
        throw new IOException("Expected password flag missing.");
      }

      byte[] decryptionSalt = new byte[AES256v3Ciphertext.ENCRYPTION_SALT_LENGTH];
      System.arraycopy(headerData, offset, decryptionSalt, 0,
          decryptionSalt.length);
      offset += decryptionSalt.length;

      byte[] hmacSalt = new byte[AES256v3Ciphertext.HMAC_SALT_LENGTH];
      System.arraycopy(headerData, offset, hmacSalt, 0, hmacSalt.length);
      offset += hmacSalt.length;

      // Derive keys
      JNCryptor cryptor = new AES256JNCryptor();
      try {
        decryptionKey = cryptor.keyForPassword(password, decryptionSalt);
        hmacKey = cryptor.keyForPassword(password, hmacSalt);
      } catch (CryptorException e) {
        throw new IOException("Failed to derive keys from password.", e);
      }

    } else {
      if (options != 0) {
        throw new IOException("Expected options byte to be zero.");
      }
    }

    byte[] iv = new byte[AES256v3Ciphertext.AES_BLOCK_SIZE];
    System.arraycopy(headerData, offset, iv, 0, iv.length);

    trailerIn = new TrailerInputStream(in, AES256v3Ciphertext.HMAC_SIZE);

    try {
      Cipher decryptCipher = Cipher
          .getInstance(AES256JNCryptor.AES_CIPHER_ALGORITHM);
      decryptCipher.init(Cipher.DECRYPT_MODE, decryptionKey,
          new IvParameterSpec(iv));

      mac = Mac.getInstance(AES256JNCryptor.HMAC_ALGORITHM);
      mac.init(hmacKey);

      // MAC the header
      mac.update(headerData);

      // The decryption stream will write the non-decrypted bytes to the mac
      // stream
      pushbackInputStream = new PushbackInputStream(new CipherInputStream(
          new MacUpdateInputStream(trailerIn, mac), decryptCipher), 1);


    } catch (GeneralSecurityException e) {
      throw new IOException("Failed to initiate cipher.", e);
    }
  }

  /**
   * Reads the next byte from the input stream. If this is the last byte in the
   * stream (determined by peeking ahead to the next byte), the value of the
   * HMAC is verified. If the verification fails an exception is thrown.
   * 
   * @return the next byte from the input stream, or {@code -1} if the end of
   *         the stream has been reached
   * @throws IOException
   *           if an I/O error occurs.
   * @throws StreamIntegrityException
   *           if the final byte has been read and the HMAC fails validation
   */
  @Override
  public int read() throws IOException, StreamIntegrityException {
    if (trailerIn == null) {
      initializeStream();
    }

    int result = pushbackInputStream.read();
    return completeRead(result);
  }

  /**
   * The {@code read(b)} method for class {@code AES256JNCryptorInputStream} has
   * the same effect as:
   * <p>
   * {@code read(b, 0, b.length)}
   * 
   * @param b
   *          the buffer into which the data is read.
   * @return the total number of bytes read into the buffer, or {@code -1} if
   *         there is no more data because the end of the stream has been
   *         reached.
   * 
   * @throws IOException
   *           if an I/O error occurs.
   * @throws StreamIntegrityException
   *           if the final byte has been read and the HMAC fails validation
   */
  @Override
  public int read(byte[] b) throws IOException, StreamIntegrityException {
    Validate.notNull(b, "Array cannot be null.");

    return read(b, 0, b.length);
  }

  /**
   * Reads a number of bytes into the byte array. If this includes the last byte
   * in the stream (determined by peeking ahead to the next byte), the value of
   * the HMAC is verified. If the verification fails an exception is thrown.
   * 
   * @param b
   *          the buffer into which the data is read.
   * @param off
   *          the start offset in array <code>b</code> at which the data is
   *          written.
   * @param len
   *          the maximum number of bytes to read.
   * @return the total number of bytes read into the buffer, or <code>-1</code>
   *         if there is no more data because the end of the stream has been
   *         reached.
   * @throws IOException
   *           If the first byte cannot be read for any reason other than end of
   *           file, or if the input stream has been closed, or if some other
   *           I/O error occurs.
   * @throws NullPointerException
   *           If <code>b</code> is <code>null</code>.
   * @throws IndexOutOfBoundsException
   *           If <code>off</code> is negative, <code>len</code> is negative, or
   *           <code>len</code> is greater than <code>b.length - off</code>
   * @throws StreamIntegrityException
   *           if the final byte has been read and the HMAC fails validation
   */
  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    Validate.notNull(b, "Byte array cannot be null.");

    Validate.isTrue(off >= 0, "Offset cannot be negative.");
    Validate.isTrue(len >= 0, "Length cannot be negative.");
    Validate.isTrue(len + off <= b.length,
        "Length plus offset cannot be longer than byte array.");

    if (len == 0) {
      return 0;
    }

    if (trailerIn == null) {
      initializeStream();
    }

    int result = pushbackInputStream.read(b, off, len);
    return completeRead(result);
  }

  /**
   * Updates the HMAC value and handles the end of stream.
   * 
   * @param b
   *          the result of a read operation
   * @return the value {@code b}
   * @throws IOException
   * @throws StreamIntegrityException
   */
  private int completeRead(int b) throws IOException, StreamIntegrityException {
    if (b == END_OF_STREAM) {
      handleEndOfStream();
    } else {
      // Have we reached the end of the stream?
      int c = pushbackInputStream.read();
      if (c == END_OF_STREAM) {
        handleEndOfStream();
      } else {
        pushbackInputStream.unread(c);
      }
    }

    return b;
  }

  /**
   * Verifies the HMAC value and throws an exception if it fails.
   * 
   * @throws IOException
   *           if the HMAC value is incorrect
   */
  private void handleEndOfStream() throws StreamIntegrityException {
    if (endOfStreamHandled) {
      return;
    }

    endOfStreamHandled = true;

    byte[] originalHMAC = trailerIn.getTrailer();
    byte[] calculateHMAC = mac.doFinal();

    if (! AES256JNCryptor.arraysEqual(originalHMAC, calculateHMAC)) {
      throw new StreamIntegrityException("MAC validation failed.");
    }
  }

  /**
   * Closes the underlying input stream.
   */
  @Override
  public void close() throws IOException {
    try {
      closeIfNotNull(pushbackInputStream);
    } finally {
      closeIfNotNull(trailerIn);
    }
  }

  private static void closeIfNotNull(InputStream in) throws IOException {
    if (in != null) {
      in.close();
    }
  }

  private static class MacUpdateInputStream extends FilterInputStream
  {
    Mac mac;
    private MacUpdateInputStream(InputStream in, Mac mac) {
      super(in);
      this.mac = mac;
    }

    public int read() throws IOException {
      int b = super.read();
      if (b >= 0)
        mac.update((byte)b);
      return b;
    }

    public int read(byte[] b, int off, int len) throws IOException {
      int n = super.read(b, off, len);
      if (n > 0)
        mac.update(b, off, n);
      return n;
    }
  }

}