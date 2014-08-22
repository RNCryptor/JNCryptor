package org.cryptonode.jncryptor;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.util.Arrays;

import org.junit.Test;

public class StreamUtilsTest {

  @Test
  public void testReadAllBytes() throws Exception {
    byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    byte[] buffer = new byte[4];

    int read = StreamUtils.readAllBytes(new SingleByteArrayInputStream(data),
        buffer);
    assertEquals(buffer.length, read);

    byte[] expected = Arrays.copyOf(data, buffer.length);
    assertArrayEquals(expected, buffer);
  }

  @Test
  public void testReadAllBytesOrFail() throws Exception {
    byte[] data = { 0, 1, 2, 3 };
    byte[] smallBuffer = new byte[2];

    StreamUtils.readAllBytesOrFail(new SingleByteArrayInputStream(data),
        smallBuffer);

    byte[] largeBuffer = new byte[data.length + 1];

    try {
      StreamUtils.readAllBytesOrFail(new SingleByteArrayInputStream(data),
          largeBuffer);
      fail();
    } catch (EOFException e) {
      // expected
    }
  }

  /**
   * Helper input stream that only returns one byte at a time.
   */
  private static class SingleByteArrayInputStream extends ByteArrayInputStream {

    public SingleByteArrayInputStream(byte[] buf) {
      super(buf);
    }

    @Override
    public synchronized int read(byte[] b, int off, int len) {
      return super.read(b, off, 1);
    }
  }
}
