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
import java.io.IOException;
import java.io.InputStream;

/**
 * Methods for operating on streams.
 */
class StreamUtils {

  /**
   * Attempts to fill the buffer by reading as many bytes as available. The
   * returned number indicates how many bytes were read, which may be smaller
   * than the buffer size if EOF was reached.
   * 
   * @param in
   *          input stream
   * @param buffer
   *          buffer to fill
   * @return the number of bytes read
   * @throws IOException
   */
  static int readAllBytes(InputStream in, byte[] buffer) throws IOException {
    int index = 0;

    while (index < buffer.length) {
      int read = in.read(buffer, index, buffer.length - index);
      if (read == -1) {
        return index;
      }
      index += read;
    }

    return index;
  }

  /**
   * Fills the buffer from the input stream. Throws exception if EOF occurs
   * before buffer is filled.
   * 
   * @param in
   *          the input stream
   * @param buffer
   *          the buffer to fill
   * @throws IOException
   */
  static void readAllBytesOrFail(InputStream in, byte[] buffer)
      throws IOException {
    int read = readAllBytes(in, buffer);
    if (read != buffer.length) {
      throw new EOFException(String.format(
          "Expected %d bytes but read %d bytes.", buffer.length, read));
    }
  }

}
