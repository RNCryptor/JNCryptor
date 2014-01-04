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

/**
 * Version 3 format.
 */
class AES256v3Ciphertext extends AES256Ciphertext {

  public AES256v3Ciphertext(byte[] data) throws InvalidDataException {
    super(data);
  }

  public AES256v3Ciphertext(byte[] encryptionSalt, byte[] hmacSalt, byte[] iv,
      byte[] ciphertext) {
    super(encryptionSalt, hmacSalt, iv, ciphertext);
  }

  public AES256v3Ciphertext(byte[] iv, byte[] ciphertext) {
    super(iv, ciphertext);
  }

  @Override
  int getVersionNumber() {
    return 3;
  }

}
