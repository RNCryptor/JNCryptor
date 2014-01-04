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

/**
 * Holds test vector data for KDF testing.
 */
class KDFTestVector {
  private final String title;
  private final int version;
  private final String password;
  private final byte[] salt;
  private final byte[] expectedKey;

  KDFTestVector(String title, int version, String password, byte[] salt,
      byte[] expectedKey) {
    this.title = title;
    this.version = version;
    this.password = password;
    this.salt = salt;
    this.expectedKey = expectedKey;
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

  byte[] getSalt() {
    return salt;
  }

  byte[] getExpectedKey() {
    return expectedKey;
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this,
        ToStringStyle.SHORT_PREFIX_STYLE);
  }

}
