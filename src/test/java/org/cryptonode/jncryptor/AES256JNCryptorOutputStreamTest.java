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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Random;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

public class AES256JNCryptorOutputStreamTest {
  private static final Random RANDOM = new Random();

  /**
   * Test reading using password constructor.
   * 
   * @throws Exception
   */
  @Test
  public void testUsingPassword() throws Exception {
    byte[] plaintext = getRandomBytes(127);

    final String password = "Testing1234";
    
    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    AES256JNCryptorOutputStream cryptorStream = new AES256JNCryptorOutputStream(byteStream, password.toCharArray());
    cryptorStream.write(plaintext);
    cryptorStream.close();
    
    byte[] encrypted = byteStream.toByteArray();
    
    JNCryptor cryptor = new AES256JNCryptor();

    byte[] result = cryptor.decryptData(encrypted, password.toCharArray());
    assertArrayEquals(plaintext, result);
  }

  /**
   * Test reading using SecretKey constructor.
   * 
   * @throws Exception
   */
  @Test
  public void testUsingKeys() throws Exception {
    byte[] plaintext = getRandomBytes(256);
    byte[] encryptionSalt = getRandomBytes(8);
    byte[] hmacSalt = getRandomBytes(8);

    final String password = "Testing1234";

    JNCryptor cryptor = new AES256JNCryptor();
    SecretKey hmacKey = cryptor.keyForPassword(password.toCharArray(), hmacSalt);
    SecretKey encryptionKey = cryptor.keyForPassword(password.toCharArray(), encryptionSalt);

    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    AES256JNCryptorOutputStream cryptorStream = new AES256JNCryptorOutputStream(byteStream, encryptionKey, hmacKey);
    cryptorStream.write(plaintext);
    cryptorStream.close();
    
    byte[] encrypted = byteStream.toByteArray();
    
    byte[] result = cryptor.decryptData(encrypted, encryptionKey, hmacKey);
    assertArrayEquals(plaintext, result);
  }

  /**
   * Test using the reference password test vectors.
   */
  @Test
  public void testReferencePasswordVectors() throws Exception {
    List<PasswordTestVector> passwordVectors = TestVectorReader.readPasswordVectors();

    for (PasswordTestVector vector : passwordVectors) {
      ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
      char[] password = vector.getPassword().toCharArray();
      AES256JNCryptorOutputStream cryptorStream = new AES256JNCryptorOutputStream(byteStream, password);
      cryptorStream.write(vector.getPlaintext());
      cryptorStream.close();
      
      byte[] encrypted = byteStream.toByteArray();
      JNCryptor cryptor = new AES256JNCryptor();
      byte[] result = cryptor.decryptData(encrypted, password);
      assertArrayEquals("Stream encryption failed for password test "+vector.getTitle(), vector.getPlaintext(), result);
    }
  }

  /**
   * Test using the reference key test vectors.
   */
  @Test
  public void testReferenceKeyVectors() throws Exception {
    List<KeyTestVector> keyVectors = TestVectorReader.readKeyVectors();

    for (KeyTestVector vector : keyVectors) {
      ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
      SecretKey key = new SecretKeySpec(vector.getEncryptionKey(), "AES");
      SecretKey hmacKey = new SecretKeySpec(vector.getHmacKey(), "AES");
      AES256JNCryptorOutputStream cryptorStream = new AES256JNCryptorOutputStream(byteStream, key, hmacKey);
      cryptorStream.write(vector.getExpectedPlaintext());
      cryptorStream.close();
      
      byte[] encrypted = byteStream.toByteArray();
      JNCryptor cryptor = new AES256JNCryptor();
      byte[] result = cryptor.decryptData(encrypted, key, hmacKey);
      assertArrayEquals("Stream encryption failed for password test "+vector.getTitle(), vector.getExpectedPlaintext(), result);
    }
  }

  /**
   * Test with a larger amount of encrypted data, and multiple write() calls.
   *
   * @throws Exception
   */
  @Test
  public void testMultipleWriteCalls() throws Exception {
    
    byte[] plaintext = getRandomBytes(50000);
    final String password = "Testing1234";

    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    AES256JNCryptorOutputStream cryptorStream = new AES256JNCryptorOutputStream(byteStream, password.toCharArray());

    byte[] buffer = new byte[16383];
    int offset = 0;
    while (offset < plaintext.length) {
        int n = Math.max(16383, plaintext.length - offset);
        cryptorStream.write(plaintext, offset, n);
        offset += n;
    }
    cryptorStream.close();
    byte[] encrypted = byteStream.toByteArray();

    JNCryptor cryptor = new AES256JNCryptor();
      
    byte[] result = cryptor.decryptData(encrypted, password.toCharArray());
    assertArrayEquals(plaintext, result);
  }

  /**
   * Test passing in a null password
   * 
   * @throws Exception
   */
  @Test(expected = NullPointerException.class)
  // TODO check for specific message
  public void testNullPassword() throws Exception {

    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    AES256JNCryptorOutputStream cryptorStream = new AES256JNCryptorOutputStream(byteStream, null);
  }

  /**
   * Test passing in an invalid password
   * 
   * @throws Exception
   */
  @Test(expected = IllegalArgumentException.class)
  // TODO check for specific message
  public void testInvalidPassword() throws Exception {

    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    AES256JNCryptorOutputStream cryptorStream = new AES256JNCryptorOutputStream(byteStream, new char[0]);
  }

  /**
   * Test passing in an invalid cipher provider
   * 
   * @throws Exception
   */
  @Test(expected = CryptorException.class)
  // TODO check for specific message
  public void testInvalidCipherProvider() throws Exception {

    String password = "Testing1234";
    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    AES256JNCryptorOutputStream cryptorStream = new AES256JNCryptorOutputStream(byteStream, password.toCharArray(), 10000, "Invalid Provider", null, null);
  }

  /**
   * Test passing in an invalid hmac provider
   * 
   * @throws Exception
   */
  @Test(expected = CryptorException.class)
  // TODO check for specific message
  public void testHMacProvider() throws Exception {

    String password = "Testing1234";
    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    AES256JNCryptorOutputStream cryptorStream = new AES256JNCryptorOutputStream(byteStream, password.toCharArray(), 10000, null, "Invalid Provider", null);
  }

  /**
   * Test passing in an invalid key provider
   * 
   * @throws Exception
   */
  @Test(expected = CryptorException.class)
  // TODO check for specific message
  public void testInvalidKeyProvider() throws Exception {

    String password = "Testing1234";
    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    AES256JNCryptorOutputStream cryptorStream = new AES256JNCryptorOutputStream(byteStream, password.toCharArray(), 10000, null, null, "Invalid Provider");
  }

  private static byte[] getRandomBytes(int length) {
    byte[] result = new byte[length];
    RANDOM.nextBytes(result);
    return result;
  }
}