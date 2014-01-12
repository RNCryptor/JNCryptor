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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

/**
 * Reads test vectors supplied by Rob Napier.
 */
class TestVectorReader {

  private static final String COMMENT_CHAR = "#";
  private static final String TITLE_FIELD = "title";
  private static final String VERSION_FIELD = "version";
  private static final String PASSWORD_FIELD = "password";
  private static final String SALT_FIELD = "salt_hex";
  private static final String KEY_FIELD = "key_hex";
  private static final String ENCRYPTION_KEY_FIELD = "enc_key_hex";
  private static final String HMAC_KEY_FIELD = "hmac_key_hex";
  private static final String IV_KEY_FIELD = "iv_hex";
  private static final String PLAINTEXT_FIELD = "plaintext_hex";
  private static final String CIPHERTEXT_FIELD = "ciphertext_hex";
  private static final String ENCRYPTION_SALT_FIELD = "enc_salt_hex";
  private static final String HMAC_SALT_FIELD = "hmac_salt_hex";

  public static void main(String[] args) throws Exception {
    List<KeyTestVector> readKeyVectors = readKeyVectors();
    for (KeyTestVector keyTestVector : readKeyVectors) {
      System.out.println(keyTestVector);
    }
  }

  static List<KDFTestVector> readKDFVectors() throws IOException {
    List<String> lines = readLinesFromTestResource("/kdf");

    final Iterator<String> iterator = lines.iterator();

    List<KDFTestVector> result = new ArrayList<KDFTestVector>();

    while (true) {
      String titleValue = readNextValue(iterator, TITLE_FIELD, false);
      if (titleValue == null) {
        // we are done
        break;
      }

      int versionValue = Integer.parseInt(readNextValue(iterator,
          VERSION_FIELD, true));

      String passwordValue = readNextValue(iterator, PASSWORD_FIELD, true);
      byte[] saltValue = DatatypeConverter.parseHexBinary(readNextValue(
          iterator, SALT_FIELD, true).replace(" ", ""));
      byte[] keyValue = DatatypeConverter.parseHexBinary(readNextValue(
          iterator, KEY_FIELD, true).replace(" ", ""));

      result.add(new KDFTestVector(titleValue, versionValue, passwordValue,
          saltValue, keyValue));
    }

    return result;
  }

  static List<KeyTestVector> readKeyVectors() throws IOException {
    List<String> lines = readLinesFromTestResource("/key");

    final Iterator<String> iterator = lines.iterator();

    List<KeyTestVector> result = new ArrayList<KeyTestVector>();

    while (true) {
      String titleValue = readNextValue(iterator, TITLE_FIELD, false);
      if (titleValue == null) {
        // we are done
        break;
      }

      int versionValue = Integer.parseInt(readNextValue(iterator,
          VERSION_FIELD, true));

      byte[] encryptionKey = DatatypeConverter.parseHexBinary(readNextValue(
          iterator, ENCRYPTION_KEY_FIELD, true).replace(" ", ""));
      byte[] hmacKey = DatatypeConverter.parseHexBinary(readNextValue(iterator,
          HMAC_KEY_FIELD, true).replace(" ", ""));
      byte[] iv = DatatypeConverter.parseHexBinary(readNextValue(iterator,
          IV_KEY_FIELD, true).replace(" ", ""));
      byte[] plaintext = DatatypeConverter.parseHexBinary(readNextValue(
          iterator, PLAINTEXT_FIELD, true).replace(" ", ""));
      byte[] ciphertext = DatatypeConverter.parseHexBinary(readNextValue(
          iterator, CIPHERTEXT_FIELD, true).replace(" ", ""));

      result.add(new KeyTestVector(titleValue, versionValue, encryptionKey,
          hmacKey, iv, plaintext, ciphertext));
    }

    return result;
  }

  static List<PasswordTestVector> readPasswordVectors() throws IOException {
    List<String> lines = readLinesFromTestResource("/password");

    final Iterator<String> iterator = lines.iterator();

    List<PasswordTestVector> result = new ArrayList<PasswordTestVector>();

    while (true) {
      String titleValue = readNextValue(iterator, TITLE_FIELD, false);
      if (titleValue == null) {
        // we are done
        break;
      }

      int versionValue = Integer.parseInt(readNextValue(iterator,
          VERSION_FIELD, true));
      String password = readNextValue(iterator, PASSWORD_FIELD, false);

      byte[] encryptionSalt = DatatypeConverter.parseHexBinary(readNextValue(
          iterator, ENCRYPTION_SALT_FIELD, true).replace(" ", ""));
      byte[] hmacSalt = DatatypeConverter.parseHexBinary(readNextValue(
          iterator, HMAC_SALT_FIELD, true).replace(" ", ""));
      byte[] iv = DatatypeConverter.parseHexBinary(readNextValue(iterator,
          IV_KEY_FIELD, true).replace(" ", ""));
      byte[] plaintext = DatatypeConverter.parseHexBinary(readNextValue(
          iterator, PLAINTEXT_FIELD, true).replace(" ", ""));
      byte[] ciphertext = DatatypeConverter.parseHexBinary(readNextValue(
          iterator, CIPHERTEXT_FIELD, true).replace(" ", ""));

      result.add(new PasswordTestVector(titleValue, versionValue, password,
          encryptionSalt, hmacSalt, iv, plaintext, ciphertext));
    }

    return result;
  }

  private static String readNextValue(Iterator<String> iterator,
      String expectedLabel, boolean throwExceptionIfMissing) throws IOException {
    String line = readNextNonCommentLine(iterator, throwExceptionIfMissing);

    if (line == null) {
      if (throwExceptionIfMissing) {
        throw new IOException("Unexpected null return value.");
      } else {
        return null;
      }
    }

    int colonIndex = line.indexOf(":");
    if (colonIndex == -1) {
      throw new IOException("No colon found in line.");
    }

    String label = line.substring(0, colonIndex).trim();
    String value = line.substring(colonIndex + 1).trim();

    if (label.equals(expectedLabel)) {
      return value;
    } else {
      throw new IOException(String.format(
          "Bad label. Expected '%s' but got '%s'.", expectedLabel, label));
    }
  }

  /**
   * Returns a trimmed version of the next non-blank line that doesn't begin
   * with a comment character.
   * 
   * @param iterator
   * @param throwExceptionIfMissing
   *          TODO
   * @return the next string, or <code>null</code> if there is none
   */
  private static String readNextNonCommentLine(Iterator<String> iterator,
      boolean throwExceptionIfMissing) throws IOException {
    while (iterator.hasNext()) {
      String trimmed = iterator.next().trim();

      if (trimmed.isEmpty()) {
        continue;
      }

      if (!trimmed.startsWith(COMMENT_CHAR)) {
        return trimmed;
      }
    }

    if (throwExceptionIfMissing) {
      throw new EOFException("Failed to read next non-comment line.");
    }

    return null;
  }

  private static List<String> readLinesFromTestResource(String resource)
      throws IOException {
    URL url = TestVectorReader.class.getResource(resource);

    if (url == null) {
      throw new FileNotFoundException(resource);
    }

    try {
      URI uri = new URI(url.toString());
      return FileUtils.readLines(new File(uri), "UTF-8");
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
  }
}
