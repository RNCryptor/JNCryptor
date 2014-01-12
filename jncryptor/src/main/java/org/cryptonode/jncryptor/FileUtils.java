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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * File handling methods.
 */
public class FileUtils {

  private FileUtils() {
  }

  /**
   * Reads lines from an input stream.
   * 
   * @param in
   *          the stream
   * @param charset
   *          the charset
   * @return a list, possibly empty, of the lines of the file
   * @throws IOException
   */
  public static List<String> readLines(InputStream in, String charset)
      throws IOException {
    BufferedReader reader = new BufferedReader(new InputStreamReader(in,
        charset));
    ArrayList<String> result = new ArrayList<String>();

    String line;
    while ((line = reader.readLine()) != null) {
      result.add(line);
    }

    return result;
  }

  /**
   * Reads lines from a file.
   * 
   * @param file
   *          the file
   * @param charset
   *          the charset
   * @return a list, possibly empty, of the lines of the file
   */
  public static List<String> readLines(File file, String charset)
      throws IOException {
    FileInputStream fis = new FileInputStream(file);
    try {
      return readLines(fis, charset);
    } finally {
      if (fis != null) {
        fis.close();
      }
    }
  }

}
