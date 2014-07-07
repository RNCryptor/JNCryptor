package org.cryptonode.jncryptor;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;

import javax.crypto.Mac;

/**
 * Helper class that processes and verifies the HMAC once it has been found (as well as not
 * including it for the client's requested input bytes).
 * @author michaelyin
 *
 */
class HmacTrailingInputStream extends PushbackInputStream {

    static final int HMAC_SIZE = 32;
    private static final int BUFFER_SIZE = 8192;
    private final byte[] hmac = new byte[HMAC_SIZE];
    private final byte[] buf = new byte[BUFFER_SIZE];
    private final Mac mac;
    private boolean haveChecked = false;

    /**
     * @param inputStream the RNCryptor stream starting at the ciphertext block
     * @param mac initialized mac to compute HMAC to verify with stream's HMAC.
     */
    public HmacTrailingInputStream(InputStream inputStream, Mac mac) {
      super(inputStream, HMAC_SIZE + 1);
      this.mac = mac;
    }

    @Override
    public int read() throws IOException {
        int read = 0;
        while (read < hmac.length) {
            int extraRead = super.read(hmac, read, hmac.length - read);
            if (extraRead == -1) {
                checkHmac();
                return -1;
            }
            read += extraRead;
        }
        int endCheck = super.read();
        if (endCheck == -1) {
            // eof
            checkHmac();
            return -1;
        }
        unread(endCheck);
        unread(hmac, 0, read);
        read = super.read();
        mac.update((byte) read);
        return read;
    }

    // constant time equality check
    private void checkHmac() throws IOException {
        if (haveChecked ) {
            return;
        }
        byte[] computedHmac = mac.doFinal();

        final int expectedLength = hmac.length;
        final int computedLength = computedHmac.length;

        int result = computedHmac.length - hmac.length;

        for (int i = 0; i < computedLength; i++) {
            result |= hmac[i % expectedLength] ^ computedHmac[i];
        }
        haveChecked = true;
        if (result != 0) {
            throw new IOException("HMAC validation failed!");
        }
    }

    // read into an internal buffer first to check if we're @ the hmac block,
    // then copy into the read buffer once we determine it's clean
    @Override
    public int read(byte[] buffer, int byteOffset, int byteCount) throws IOException {
        int read = 0;
        while (read < hmac.length) {
            int extraRead = super.read(hmac, read, hmac.length - read);
            if (extraRead == -1) {
                checkHmac();
                return -1;
            }
            read += extraRead;
        }
        int endCheck = super.read();
        if (endCheck == -1) {
            // eof
            checkHmac();
            return -1;
        }
        unread(endCheck);
        unread(hmac, 0, read);

        read = 0;
        while (byteCount > 0) {
            int readLength = buf.length;
            if (byteCount + hmac.length < buf.length) {
                readLength = byteCount + hmac.length;
            }
            int curRead = 0;
            // ensure we've retrieved at least hmac.length
            while (curRead < hmac.length) {
                int extraRead = super.read(buf, curRead, readLength - curRead);
                if (extraRead == -1) {
                    throw new IOException("Unexpectedly hit end of stream before encountering HMAC.");
                }
                curRead += extraRead;
            }
            endCheck = super.read();
            if (endCheck == -1) {
                // hit end of stream, extract HMAC, copy the rest to client buffer
                curRead -= hmac.length;
                System.arraycopy(buf, curRead, hmac, 0, hmac.length);
                System.arraycopy(buf, 0, buffer, byteOffset, curRead);
                mac.update(buffer, byteOffset, read + curRead);
                checkHmac();
                return read + curRead;
            } else {
                // unread the extra hmac checking bytes, copy the rest to client buffer
                unread(endCheck);
                curRead -= hmac.length;
                System.arraycopy(buf, curRead, hmac, 0, hmac.length);
                unread(hmac);
                System.arraycopy(buf, 0, buffer, byteOffset, curRead);
                mac.update(buffer, byteOffset, curRead);
            }
            byteOffset += curRead;
            byteCount -= curRead;
            read += curRead;
        }
        return read;
    }

    @Override
    public long skip(long byteCount) throws IOException {
        long skippedBytes = 0;
        byte[] buf = new byte[BUFFER_SIZE];
        while (byteCount > 0) {
            if (byteCount < buf.length) {
                return read(buf, 0, (int) byteCount) + skippedBytes;
            }
            skippedBytes += read(buf, 0, buf.length);
            byteCount -= buf.length;
        }
        return skippedBytes;
    }
}
