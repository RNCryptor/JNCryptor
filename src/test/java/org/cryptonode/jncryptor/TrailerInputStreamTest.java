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
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Random;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.Test;

/**
 * 
 */
public class TrailerInputStreamTest {

  private static final Random RANDOM = new Random();

  /**
   * Tests a basic read.
   * 
   * @throws Exception
   */
  @Test
  public void testBasicRead() throws Exception {
    byte[] trailer = new byte[10];
    RANDOM.nextBytes(trailer);

    byte[] data = new byte[30];
    RANDOM.nextBytes(data);

    byte[] streamData = ArrayUtils.addAll(data, trailer);

    TrailerInputStream tis = new TrailerInputStream(new ByteArrayInputStream(
        streamData), trailer.length);

    try {

      for (int i = 0; i < 30; i++) {
        byte b = (byte) tis.read();
        assertEquals(b, data[i]);
      }

      assertEquals(-1, tis.read());
      assertArrayEquals(trailer, tis.getTrailer());

    } finally {
      tis.close();
    }
  }

  /**
   * Tests an EOF occurs if the data is too small.
   * 
   * @throws Exception
   */
  @Test(expected = EOFException.class)
  public void testEOF() throws Exception {
    TrailerInputStream tis = new TrailerInputStream(new ByteArrayInputStream(
        new byte[4]), 5);
    IOUtils.toByteArray(tis);
  }

  /**
   * Tests the stream copes with data that just contains the trailer.
   * 
   * @throws Exception
   */
  @Test
  public void testTrailerOnly() throws Exception {
    TrailerInputStream tis = new TrailerInputStream(new ByteArrayInputStream(
        new byte[5]), 5);
    byte[] result = IOUtils.toByteArray(tis);
    assertTrue(result.length == 0);
  }

  /**
   * Tests the multi-byte stream read method works correctly when the requested
   * byte length is smaller than the trailer size.
   * 
   * @throws Exception
   */
  @Test
  public void testMultiByteReadWithRequestSmallerThanTrailer() throws Exception {
    testMultiByteRead(5, 2);
  }

  /**
   * Tests the multi-byte stream read method works correctly when the requested
   * byte length is larger than the trailer size.
   * 
   * @throws Exception
   */
  @Test
  public void testMultiByteReadWithRequestLargerThanTrailer() throws Exception {
    testMultiByteRead(5, 7);
  }

  private void testMultiByteRead(int trailerSize, int readSize)
      throws IOException {

    byte[] inputData = new byte[10];
    RANDOM.nextBytes(inputData);

    byte[] trailerData = new byte[5];
    RANDOM.nextBytes(trailerData);

    byte[] data = ArrayUtils.addAll(inputData, trailerData);

    TrailerInputStream tis = new TrailerInputStream(new ByteArrayInputStream(
        data), trailerSize);
    try {
      byte[] buffer = new byte[readSize];
      IOUtils.readFully(tis, buffer);

      byte[] expectedValue = new byte[readSize];
      System.arraycopy(inputData, 0, expectedValue, 0, readSize);

      assertArrayEquals("Wrong read value", expectedValue, buffer);

      // check trailer
      while (tis.read() != -1) {
      }

      assertArrayEquals("Wrong trailer value", trailerData, tis.getTrailer());
    } finally {
      tis.close();
    }
  }

  @Test
  public void testSanity() {

    for (int i = 0; i < 10000; i++) {
      byte[] inputData = new byte[15];
      RANDOM.nextBytes(inputData);

      ByteArrayInputStream in = new ByteArrayInputStream(inputData);
      int count = 0;
      while (in.read() != -1) {
        count++;
      }

      assertTrue(count == 15);
    }

  }
}