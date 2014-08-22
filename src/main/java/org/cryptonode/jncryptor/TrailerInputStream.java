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
 * A wrapper for an input stream that contains trailer data.
 */
public class TrailerInputStream extends InputStream {

  /**
   * Byte value indicating the end of stream.
   */
  private static final int EOF_VALUE = -1;

  private final int trailerSize;
  private final InputStream in;

  private byte[] trailerBuffer;

  /**
   * Creates a {@code TrailerInputStream} that wraps another stream.
   * 
   * @param in
   *          the stream to read from
   * @param trailerSize
   *          the byte length of the trailer
   */
  public TrailerInputStream(InputStream in, int trailerSize) {

    Validate.notNull(in, "InputStream cannot be null.");
    Validate.isTrue(trailerSize > -1, "Trailer size cannot be negative.");

    this.in = in;
    this.trailerSize = trailerSize;
  }

  /**
   * Populates the trailer buffer with data from the stream.
   * 
   * @throws EOFException
   *           if the stream finishes before the trailer is read
   * @throws IOException
   *           if the underlying stream throws an exception
   */
  private void fillTrailerBuffer() throws IOException {
    trailerBuffer = new byte[trailerSize];

    if (trailerSize == 0) {
      return;
    }

    int bytesRead = StreamUtils.readAllBytes(in, trailerBuffer);
    if (bytesRead != trailerBuffer.length) {
      throw new EOFException(String.format(
          "Trailer size was %d bytes but stream only contained %d bytes.",
          trailerSize, bytesRead));
    }
  }

  /**
   * Reads the next byte from the underlying {@code InputStream}. This method
   * returns {@code -1} when the last byte before the trailer has been read.
   * 
   * @return the next non-trailer byte from the underlying stream, or {@code -1}
   * 
   * @throws EOFException
   *           if the stream contains less data than the size of the trailer
   * @throws IOException
   *           if the underlying stream throws an exception
   */
  @Override
  public int read() throws IOException {
    if (trailerBuffer == null) {
      fillTrailerBuffer();
    }

    int nextByte = in.read();

    if (nextByte == EOF_VALUE) {
      return nextByte;
    }

    if (trailerBuffer.length == 0) {
      return nextByte;
    }

    int result = trailerBuffer[0] & 0xFF; // must be positive

    System.arraycopy(trailerBuffer, 1, trailerBuffer, 0,
        trailerBuffer.length - 1);
    trailerBuffer[trailerBuffer.length - 1] = (byte) nextByte;

    return result;
  }

  /**
   * Has the same affect as {@code read(b, 0, b.length)}.
   */
  @Override
  public int read(byte[] b) throws IOException {
    return read(b, 0, b.length);
  }

  /**
   * Reads up to {@code len} non-trailer bytes from the underlying stream into
   * the array {@code b}, beginning at offset {@code off}.
   * 
   * @param b
   *          the buffer into which the data is read.
   * @param off
   *          the start offset in array {@code b} at which the data is written.
   * @param len
   *          the maximum number of bytes to read.
   * @return the total number of bytes read into the buffer, or {@code -1} if
   *         there is no more data because the end of the stream has been
   *         reached.
   * 
   * @throws IOException
   *           If the first byte cannot be read for any reason other than end of
   *           file, or if the input stream has been closed, or if there are
   *           insufficient bytes in the underlying stream to read the trailer,
   *           or if some other I/O error occurs.
   */
  @Override
  public int read(byte[] b, int off, int len) throws IOException {

    // Sanity checks taken from InputStream
    if (b == null) {
      throw new NullPointerException();
    } else if (off < 0 || len < 0 || len > b.length - off) {
      throw new IndexOutOfBoundsException();
    } else if (len == 0) {
      return 0;
    }

    if (trailerBuffer == null) {
      fillTrailerBuffer();
    }

    byte[] inputBuffer = new byte[len];
    int numBytesRead = in.read(inputBuffer);

    if (numBytesRead == EOF_VALUE) {
      return numBytesRead;
    }

    if (trailerSize == 0) {
      System.arraycopy(inputBuffer, 0, b, off, numBytesRead);
      return numBytesRead;
    }

    if (numBytesRead <= trailerSize) {
      // Need some of the trailer
      System.arraycopy(trailerBuffer, 0, b, off, numBytesRead);

      // Now need to shift rear of trailer to front
      System.arraycopy(trailerBuffer, numBytesRead, trailerBuffer, 0,
          trailerSize - numBytesRead);

      // Now need to fill rear of trailer
      System.arraycopy(inputBuffer, 0, trailerBuffer, trailerSize
          - numBytesRead, numBytesRead);

    } else {
      // Need all the trailer
      System.arraycopy(trailerBuffer, 0, b, off, trailerSize);
      off += trailerSize;

      // Need the remaining data, except enough to fill the buffer
      System.arraycopy(inputBuffer, 0, b, off, numBytesRead - trailerSize);

      // Finally, fill the buffer from the remaining input
      System.arraycopy(inputBuffer, numBytesRead - trailerSize, trailerBuffer,
          0, trailerSize);
    }

    return numBytesRead;
  }

  @Override
  public int available() throws IOException {
    if (trailerBuffer == null) {
      return Math.max(0, in.available() - trailerSize);
    }

    return in.available();
  }

  @Override
  public void close() throws IOException {
    in.close();
  }

  /**
   * The {@code mark} and {@code reset} methods are not supported in this
   * stream.
   * 
   * @return {@code false}
   */
  @Override
  public boolean markSupported() {
    return false;
  }

  /**
   * Returns the trailer data. The result of this method will be inaccurate
   * unless the entire underlying stream has been read.
   * 
   * @return the trailer data, or {@code null} if no bytes have been read using
   *         the {@code read} methods
   */
  public byte[] getTrailer() {
    return trailerBuffer.clone();
  }

}
