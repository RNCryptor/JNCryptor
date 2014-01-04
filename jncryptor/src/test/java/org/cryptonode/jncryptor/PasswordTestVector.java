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

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/*
 * Holds test vector data for password testing.
 */
class PasswordTestVector {

  private final String title;
  private final int version;
  private final String password;
  private final byte[] encryptionSalt;
  private final byte[] hmacSalt;
  private final byte[] iv;
  private final byte[] plaintext;
  private final byte[] ciphertext;

  PasswordTestVector(String title, int version, String password,
      byte[] encryptionSalt, byte[] hmacSalt, byte[] iv, byte[] plaintext,
      byte[] ciphertext) {
    this.title = title;
    this.version = version;
    this.password = password;
    this.encryptionSalt = encryptionSalt;
    this.hmacSalt = hmacSalt;
    this.iv = iv;
    this.plaintext = plaintext;
    this.ciphertext = ciphertext;
  }

  String getTitle() {
    return title;
  }

  int getVersion() {
    return version;
  }

  String getPassword() {
    return password;
  }

  byte[] getEncryptionSalt() {
    return encryptionSalt;
  }

  byte[] getHmacSalt() {
    return hmacSalt;
  }

  byte[] getIv() {
    return iv;
  }

  byte[] getPlaintext() {
    return plaintext;
  }

  byte[] getCiphertext() {
    return ciphertext;
  }

  /*
   * (non-Javadoc)
   * 
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this,
        ToStringStyle.SHORT_PREFIX_STYLE);
  }
}
