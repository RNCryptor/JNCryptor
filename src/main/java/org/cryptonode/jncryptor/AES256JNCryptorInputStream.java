package org.cryptonode.jncryptor;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * Perform password based decryption, based on <a href="https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md">v3 of the RNCryptor spec</a>.
 * 
 * The last 32 bytes of the stream is the HMAC. This stream will not return the HMAC bytes
 * when reading, and will instead verify the HMAC when it is read and throw an {@link IOException}
 * if it fails the check.
 * @author michaelyin
 *
 */
public class AES256JNCryptorInputStream extends InputStream {

  private static final int ENCRYPTION_KEY_LENGTH = AES256JNCryptor.AES_256_KEY_SIZE * 8;
  private final CipherInputStream stream;

  /**
   * Create a decrypting input stream by wrapping an existing input stream containing the
   * encrypted data.
   * @param inputStream the input stream that has been encrypted to the RNCryptor v3 spec
   * @param password the password to decrypt with
   * @throws IllegalStateException if the file is encrypted with something other than version 3
   * @throws IOException failed to read RNCryptor header
   * @throws NoSuchAlgorithmException specific AES encryption algorithm not supported
   * @throws InvalidKeySpecException error with the key
   * @throws InvalidKeyException error with the key
   * @throws NoSuchPaddingException encryption padding not supported
   * @throws InvalidAlgorithmParameterException problem decrypting stream
   */
  public AES256JNCryptorInputStream(InputStream inputStream, char[] password)
      throws IllegalStateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException,
      InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
    Validate.notNull(password, "Password cannot be null.");
    Validate.isTrue(password.length > 0, "Password cannot be empty.");

    /*
     * Byte:     |    0    |    1    |      2-9       |  10-17   | 18-33 | <-      ...     -> | n-32 - n |
     * Contents: | version | options | encryptionSalt | HMACSalt |  IV   | ... ciphertext ... |   HMAC   |
     */
    int version = inputStream.read();
    if (version != AES256JNCryptor.VERSION) {
      throw new IllegalStateException("Invalid encrypted header version. Expected 3, got " + version);
    }
    // options byte, assume pw encryption
    inputStream.read();
    byte[] salt = new byte[8];
    byte[] hmacSalt = new byte[8];
    byte[] iv = new byte[16];
    inputStream.read(salt);
    inputStream.read(hmacSalt);
    inputStream.read(iv);
    final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(AES256JNCryptor.KEY_DERIVATION_ALGORITHM);
    final KeySpec hmacKeySpec = new PBEKeySpec(password, hmacSalt, AES256JNCryptor.PBKDF_DEFAULT_ITERATIONS, ENCRYPTION_KEY_LENGTH);
    final SecretKey hmacKey = keyFactory.generateSecret(hmacKeySpec);
    final Mac mac = Mac.getInstance(AES256JNCryptor.HMAC_ALGORITHM);
    mac.init(hmacKey);
    mac.update(AES256JNCryptor.VERSION_OPTIONS);
    mac.update(salt);
    mac.update(hmacSalt);
    mac.update(iv);

    final HmacTrailingInputStream formatStream = new HmacTrailingInputStream(inputStream, mac);
    final KeySpec keySpec = new PBEKeySpec(password, salt, AES256JNCryptor.PBKDF_DEFAULT_ITERATIONS, ENCRYPTION_KEY_LENGTH);
    Cipher cipher = Cipher.getInstance(AES256JNCryptor.AES_CIPHER_ALGORITHM);
    IvParameterSpec ivParams = new IvParameterSpec(iv);
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), AES256JNCryptor.AES_NAME), ivParams);

    stream = new CipherInputStream(formatStream, cipher);
  }
  
  @Override
  public int read() throws IOException {
    return stream.read();
  }
  
  @Override
  public int read(byte[] b) throws IOException {
    return stream.read(b);
  }
  
  @Override
  public synchronized void mark(int readlimit) {
    stream.mark(readlimit);
  }
  
  @Override
  public int available() throws IOException {
    return stream.available();
  }
  
  @Override
  public void close() throws IOException {
    stream.close();
  }
  
  @Override
  public boolean markSupported() {
    return stream.markSupported();
  }
  
  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    return stream.read(b, off, len);
  }
  
  @Override
  public synchronized void reset() throws IOException {
    stream.reset();
  }
  
  @Override
  public long skip(long n) throws IOException {
    return stream.skip(n);
  }
}
