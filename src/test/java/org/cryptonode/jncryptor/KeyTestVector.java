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


/*
 * Holds test vector data for key testing.
 */
class KeyTestVector {

  private final String title;
  private final int version;
  private final byte[] encryptionKey;
  private final byte[] hmacKey;
  private final byte[] iv;
  private final byte[] plaintext;
  private final byte[] ciphertext;

  KeyTestVector(String title, int version, byte[] encryptionKey,
      byte[] hmacKey, byte[] iv, byte[] plaintext, byte[] expectedCiphertext) {
    this.title = title;
    this.version = version;
    this.encryptionKey = encryptionKey;
    this.hmacKey = hmacKey;
    this.iv = iv;
    this.plaintext = plaintext;
    this.ciphertext = expectedCiphertext;
  }

  String getTitle() {
    return title;
  }

  int getVersion() {
    return version;
  }

  byte[] getEncryptionKey() {
    return encryptionKey;
  }

  byte[] getHmacKey() {
    return hmacKey;
  }

  byte[] getIv() {
    return iv;
  }

  byte[] getExpectedPlaintext() {
    return plaintext;
  }

  byte[] getCiphertext() {
    return ciphertext;
  }

}
