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

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.TeeInputStream;

/**
 * 
 */
public class AES256JNCryptorInputStream extends InputStream {

  private static final int END_OF_STREAM = -1;
  private final boolean isPasswordEncrypted;
  private final InputStream in;

  private char[] password;
  private SecretKey decryptionKey;
  private SecretKey hmacKey;

  private TrailerInputStream trailerIn;
  private CipherInputStream decryptionStream;
  private ByteArrayOutputStream rawInputStream;
  private Mac mac;

  /**
   * Creates an input stream for password-encrypted data.
   * 
   * @param in
   *          the {@code InputStream} to read
   * @param password
   *          the password
   */
  AES256JNCryptorInputStream(InputStream in, char[] password) {
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
  AES256JNCryptorInputStream(InputStream in, SecretKey decryptionKey,
      SecretKey hmacKey) {
    isPasswordEncrypted = false;
    this.decryptionKey = decryptionKey;
    this.hmacKey = hmacKey;
    this.in = in;
  }

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
    IOUtils.readFully(in, headerData); // throws EOF if insufficient data

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

      // The available() method is far from perfect, but it is better than no
      // guess
      // at all.
      rawInputStream = new ByteArrayOutputStream(trailerIn.available());

      // The decryption stream will write the non-decrypted bytes to the mac
      // stream
      decryptionStream = new CipherInputStream(new TeeInputStream(trailerIn,
          rawInputStream), decryptCipher);

      mac = Mac.getInstance(AES256JNCryptor.HMAC_ALGORITHM);
      mac.init(hmacKey);

      // MAC the header
      mac.update(headerData);

    } catch (GeneralSecurityException e) {
      throw new IOException("Failed to initiate cipher.", e);
    }
  }

  @Override
  public int read() throws IOException {
    if (trailerIn == null) {
      initializeStream();
    }

    int result = decryptionStream.read();
    if (result == END_OF_STREAM) {
      handleEndOfStream();
    } else {
      mac.update(rawInputStream.toByteArray());
      rawInputStream.reset();
    }

    return result;
  }

  @Override
  public int read(byte[] b) throws IOException {
    return read(b, 0, b.length);
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    if (trailerIn == null) {
      initializeStream();
    }

    int result = decryptionStream.read(b, off, len);
    if (result == END_OF_STREAM) {
      handleEndOfStream();
    } else {
      // update mac
      mac.update(rawInputStream.toByteArray());
      rawInputStream.reset();
    }

    return result;
  }

  /**
   * Verifies the HMAC value and throws an exception if it fails.
   * 
   * @throws IOException
   *           if the HMAC value is incorrect
   */
  private void handleEndOfStream() throws IOException {
    byte[] originalHMAC = trailerIn.getTrailer();
    byte[] calculateHMAC = mac.doFinal();
    if (!Arrays.equals(originalHMAC, calculateHMAC)) {
      throw new IOException("MAC validation failed.");
    }
  }

  /**
   * Closes the underlying input stream.
   */
  @Override
  public void close() throws IOException {
    try {
      closeIfNotNull(decryptionStream);
    } finally {
      closeIfNotNull(trailerIn);
    }
  }

  private static void closeIfNotNull(InputStream in) throws IOException {
    if (in != null) {
      in.close();
    }
  }
}