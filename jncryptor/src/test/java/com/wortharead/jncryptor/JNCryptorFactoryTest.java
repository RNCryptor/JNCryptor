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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.net.URL;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import com.wortharead.jncryptor.JNCryptor;
import com.wortharead.jncryptor.JNCryptorFactory;

/**
 * 
 */
public class JNCryptorFactoryTest {

  /**
   * Tests the factory correctly returns the version specified. Note: this test
   * is currently ineffectual, thanks to there being only one version number.
   * 
   * @throws Exception
   */
  @Test
  public void testGetCorrectVersion() throws Exception {
    final int version = 1;
    JNCryptor cryptor = JNCryptorFactory.getCryptor(version);
    assertEquals(version, cryptor.getVersionNumber());
  }

  /**
   * Loads the file listing the classnames of the {@link JNCryptor}s and
   * confirms the {@link JNCryptorFactory} returns all the classes listed in the
   * file.
   * 
   * @throws Exception
   */
  @Test
  public void testGetAllCryptors() throws Exception {
    /*
     * Call this first to ensure the factory has loaded all the cryptors.
     */
    List<JNCryptor> cryptors = JNCryptorFactory.getCryptors();

    // Find the resource file ourselves
    URL url = JNCryptorFactoryTest.class.getResource("/jncryptor-classes.txt");

    if (url == null) {
      fail("Cannot find cryptor class list.");
    }

    List<String> classList = FileUtils.readLines(new File(url.getPath()));

    // Check each class actually exists
    for (String clazz : classList) {
      try {
        Class.forName(clazz);
      } catch (ClassNotFoundException e) {
        fail(String.format("Could not find class: %s", clazz));
      }
    }

    // Check the returned list contains all the classes listed in the file

    assertEquals(classList.size(), cryptors.size());

    for (JNCryptor cryptor : cryptors) {
      assertTrue(classList.contains(cryptor.getClass().getCanonicalName()));
    }
  }

  /**
   * Checks the correct cryptor is returned when the factory is given ciphertext
   * encrypted by that cryptor.
   * 
   * @throws Exception
   */
  @Test
  public void testVersionForCiphertext() throws Exception {
    JNCryptor cryptor = JNCryptorFactory.getCryptor();

    byte[] ciphertext = cryptor.encryptData("Foo".getBytes(),
        "Bar".toCharArray());
    assertEquals(cryptor, JNCryptorFactory.getCryptorForCiphertext(ciphertext));
  }
}
