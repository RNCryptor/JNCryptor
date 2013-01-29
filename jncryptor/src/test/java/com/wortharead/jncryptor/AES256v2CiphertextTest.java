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

import static org.junit.Assert.assertEquals;

import java.util.Random;

import org.junit.Test;

import com.wortharead.jncryptor.AES256v2Ciphertext;
import com.wortharead.jncryptor.InvalidDataException;

/**
 * 
 */
public class AES256v2CiphertextTest {

  /**
   * Some simple random data of the correct size.
   */
  private static class ExampleData {
    private static final byte[] ENCRYPTION_SALT = new byte[AES256v2Ciphertext.ENCRYPTION_SALT_LENGTH];
    private static final byte[] HMAC_SALT = new byte[AES256v2Ciphertext.HMAC_SALT_LENGTH];
    private static final byte[] IV = new byte[AES256v2Ciphertext.AES_BLOCK_SIZE];
    private static final byte[] CIPHERTEXT = new byte[AES256v2Ciphertext.AES_BLOCK_SIZE];
    private static final byte[] HMAC = new byte[AES256v2Ciphertext.HMAC_SIZE];

    static {
      Random random = new Random();
      random.nextBytes(ENCRYPTION_SALT);
      random.nextBytes(HMAC_SALT);
      random.nextBytes(IV);
      random.nextBytes(CIPHERTEXT);
      random.nextBytes(HMAC);
    }
  }

  @Test
  public void circularTest() throws Exception {

    AES256v2Ciphertext data = new AES256v2Ciphertext(ExampleData.ENCRYPTION_SALT,
        ExampleData.HMAC_SALT, ExampleData.IV, ExampleData.CIPHERTEXT);

    data.setHmac(ExampleData.HMAC);
    byte[] rawData = data.getRawData();

    AES256v2Ciphertext data2 = new AES256v2Ciphertext(rawData);

    assertEquals(data, data2);
  }

  @Test(expected = NullPointerException.class)
  public void testNPE() throws Exception {
    new AES256v2Ciphertext(null);
  }

  @Test(expected = InvalidDataException.class)
  public void testMinimumLength() throws Exception {

    // data is one byte short of minimum
    byte[] data = new byte[AES256v2Ciphertext.MINIMUM_LENGTH_WITH_PASSWORD - 1];
    new AES256v2Ciphertext(data);
  }

  @Test(expected = InvalidDataException.class)
  public void testZeroVersion() throws Exception {
    byte[] data = new byte[AES256v2Ciphertext.MINIMUM_LENGTH_WITH_PASSWORD];
    new AES256v2Ciphertext(data);
  }

  @Test(expected = InvalidDataException.class)
  public void testInvalidOption() throws Exception {
    byte[] data = new byte[AES256v2Ciphertext.MINIMUM_LENGTH_WITH_PASSWORD];
    data[0] = 1; // Version 1 = correct
    data[1] = 2; // Options = 2 (incorrect)

    new AES256v2Ciphertext(data);
  }

  @Test
  public void testSimple() throws Exception {
    byte[] data = new byte[AES256v2Ciphertext.MINIMUM_LENGTH_WITH_PASSWORD];
    data[0] = 2; // Version 1 = correct
    data[1] = 1; // Option = 0x01 (has password)

    new AES256v2Ciphertext(data);
  }
}
