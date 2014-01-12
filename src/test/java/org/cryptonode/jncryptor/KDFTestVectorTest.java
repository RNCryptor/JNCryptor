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

import javax.crypto.SecretKey;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class KDFTestVectorTest {

  private final KDFTestVector vector;

  public KDFTestVectorTest(KDFTestVector vector) {
    this.vector = vector;
  }

  @Parameters
  public static Collection<Object[]> makeParameters() throws IOException {
    List<KDFTestVector> kdfVectors = TestVectorReader.readKDFVectors();
    List<Object[]> result = new ArrayList<Object[]>();
    for (KDFTestVector kdfTestVector : kdfVectors) {
      result.add(new Object[] { kdfTestVector });
    }

    return result;
  }

  @Test
  public void testKDFVector() throws Exception {
    JNCryptor cryptor = new AES256JNCryptor();

    assertEquals("Test not suitable for current version.",
        cryptor.getVersionNumber(), vector.getVersion());

    SecretKey secretKey = cryptor.keyForPassword(vector.getPassword()
        .toCharArray(), vector.getSalt());
    assertArrayEquals(vector.getTitle(), vector.getExpectedKey(),
        secretKey.getEncoded());
  }
}
