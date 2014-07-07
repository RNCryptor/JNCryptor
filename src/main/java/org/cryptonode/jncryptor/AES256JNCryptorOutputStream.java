package org.cryptonode.jncryptor;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A wrapper stream that encrypts according to the <a href="https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md">RNCryptor v3 spec</a>.
 * Since HMAC requires all of the encrypted data to be written first, it is written when the stream
 * is closed. If you don't want to close the stream yet, you can alternatively call
 * {@link #finish()} to make sure the HMAC is written after writing all the encrypted data.
 * @author michaelyin
 *
 */
public class AES256JNCryptorOutputStream extends FilterOutputStream {

  private static final int ENCRYPTION_KEY_LENGTH = AES256JNCryptor.AES_256_KEY_SIZE * 8;

  private final Cipher cipher;
  private final Mac mac;
  private boolean finished = false;

  /**
   * Creates an output stream that outputs in the RNCryptor v3 spec into the given output stream.
   * @param outputStream the stream to receive encrypted data
   * @param password password to encrypt with
   * @return a stream that will encrypt data and send it to the wrapped stream.
   * @throws IOException
   */
  public AES256JNCryptorOutputStream(OutputStream out, char[] password) throws IOException {
    this(out, password, null, null, null);
  }

  /**
   * Used for testing to inject salts instead of using a random salts.
   */
  // visible for testing
  AES256JNCryptorOutputStream(OutputStream out, final char[] password, byte[] salt, byte[] hmacSalt,
      byte[] iv) throws IOException {
    super(out);
    Validate.notNull(password, "Password cannot be null.");
    Validate.isTrue(password.length > 0, "Password cannot be empty.");

    final SecureRandom random = new SecureRandom();
    if (salt == null || hmacSalt == null || iv == null) {
      salt = new byte[8];
      hmacSalt = new byte[8];
      iv = new byte[16];
      random.nextBytes(salt);
      random.nextBytes(hmacSalt);
      random.nextBytes(iv);
    }

    try {
      final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(AES256JNCryptor.KEY_DERIVATION_ALGORITHM);
      cipher = Cipher.getInstance(AES256JNCryptor.AES_CIPHER_ALGORITHM);
      final KeySpec keySpec = new PBEKeySpec(password, salt, AES256JNCryptor.PBKDF_DEFAULT_ITERATIONS, ENCRYPTION_KEY_LENGTH);
      final SecretKey key = new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), AES256JNCryptor.AES_NAME);

      final KeySpec hmacKeySpec = new PBEKeySpec(password, hmacSalt, AES256JNCryptor.PBKDF_DEFAULT_ITERATIONS, ENCRYPTION_KEY_LENGTH);
      final SecretKey hmacKey = keyFactory.generateSecret(hmacKeySpec);

      final IvParameterSpec ivParams = new IvParameterSpec(iv);
      cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);

      mac = Mac.getInstance(AES256JNCryptor.HMAC_ALGORITHM);
      mac.init(hmacKey);

      mac.update(AES256JNCryptor.VERSION_OPTIONS);
      out.write(AES256JNCryptor.VERSION_OPTIONS);
      mac.update(salt);
      out.write(salt);
      mac.update(hmacSalt);
      out.write(hmacSalt);
      mac.update(iv);
      out.write(iv);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("This device does not support encrpytion algorithm. Cannot decrypt.", e);
    } catch (NoSuchPaddingException e) {
      throw new IllegalStateException("This device does not support the expected encryption padding. Cannot decrypt.", e);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException("Error with key. Cannot decrypt.", e);
    } catch (InvalidKeySpecException e) {
      throw new IllegalStateException("Error with key. Cannot decrypt.", e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalStateException("Problem decrypting stream.", e);
    }
  }

  @Override
  public void write(byte[] buffer, int offset, int length) throws IOException {
    if (length == 0) {
      return;
    }
    byte[] result = cipher.update(buffer, offset, length);
    if (result != null) {
      mac.update(result);
      out.write(result);
    }
  }

  // all writes get funneled into the write(buffer, offset, length) form
  @Override
  public void write(int oneByte) throws IOException {
    final byte[] buffer = new byte[1];
    buffer[0] = (byte) (oneByte & 0xff);
    write(buffer);
  }

  /**
   * Finish the encryption without closing the underlying stream.
   */
  public void finish() throws IOException {
    if (!finished) {
      try {
        byte[] finalBytes = cipher.doFinal();
        out.write(finalBytes);
        byte[] hmac = mac.doFinal(finalBytes);
        out.write(hmac);
        out.flush();
      } catch (IllegalBlockSizeException e) {
        throw new IOException(e);
      } catch (BadPaddingException e) {
        throw new IOException(e);
      } finally {
        finished = true;
      }
    }
  }

  @Override
  public void close() throws IOException {
    finish();
    super.close();
  }
}
