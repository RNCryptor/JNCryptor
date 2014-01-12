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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PasswordTestVectorTest {

  private final PasswordTestVector vector;

  public PasswordTestVectorTest(PasswordTestVector vector) {
    this.vector = vector;
  }

  @Parameters
  public static Collection<Object[]> makeParameters() throws IOException {
    List<PasswordTestVector> passwordVectors = TestVectorReader
        .readPasswordVectors();
    List<Object[]> result = new ArrayList<Object[]>();
    for (PasswordTestVector passwordTestVector : passwordVectors) {
      result.add(new Object[] { passwordTestVector });
    }

    return result;
  }

  @Test
  public void testKeyVector() throws Exception {
    AES256JNCryptor cryptor = new AES256JNCryptor();

    assertEquals("Test not suitable for current version.",
        cryptor.getVersionNumber(), vector.getVersion());

    byte[] ciphertext = cryptor.encryptData(vector.getPlaintext(), vector
        .getPassword().toCharArray(), vector.getEncryptionSalt(), vector
        .getHmacSalt(), vector.getIv());
    assertArrayEquals(vector.getTitle(), vector.getCiphertext(), ciphertext);
  }
}
