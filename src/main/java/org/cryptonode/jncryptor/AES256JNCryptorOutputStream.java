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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * Writes RNCryptor-format (version 3) data in a stream fashion.  The stream must be closed to properly write
 * the data.
 */
public class AES256JNCryptorOutputStream extends FilterOutputStream
{
    private static final String AES_NAME = "AES";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int PBKDF_DEFAULT_ITERATIONS = 10000;
    private static final int VERSION = 3;
    private static final int AES_256_KEY_SIZE = 256 / 8;

    private JNCryptorCipherOutputStream cipherOut; // The cipher stream we write plaintext to
    private JNCryptorMacOutputStream hmacOut;      // An intermediate stream which updates the Mac object
    private OutputStream finalOut;                 // The destination output stream.

    private SecretKey passwordKey;
    private SecretKey hmacKey;
    private byte[] passwordSalt;
    private byte[] hmacSalt;
    private byte[] iv;
    private int iterations;
    private boolean writtenHeader;

    private static JNCryptorCipherOutputStream getCipherStream(Object cipherProvider, Object hmacProvider, OutputStream out)
    throws CryptorException
    {
        Cipher cipher = null;
        try
        {
            if (cipherProvider instanceof Provider)
                cipher = Cipher.getInstance(AES256JNCryptor.AES_CIPHER_ALGORITHM, (Provider)cipherProvider);
            else if (cipherProvider instanceof String)
                cipher = Cipher.getInstance(AES256JNCryptor.AES_CIPHER_ALGORITHM, (String)cipherProvider);
            else
                cipher = Cipher.getInstance(AES256JNCryptor.AES_CIPHER_ALGORITHM);
        }
        catch (GeneralSecurityException e)
        {
            throw new CryptorException("Unable to create Cipher", e);
        }
        
        Mac mac = null;
        try
        {
            if (hmacProvider instanceof Provider)
                mac = Mac.getInstance(AES256JNCryptor.HMAC_ALGORITHM, (Provider)hmacProvider);
            else if (hmacProvider instanceof String)
                mac = Mac.getInstance(AES256JNCryptor.HMAC_ALGORITHM, (String)hmacProvider);
            else
                mac = Mac.getInstance(AES256JNCryptor.HMAC_ALGORITHM);
        }
        catch (GeneralSecurityException e)
        {
            throw new CryptorException("Unable to create Mac", e);
        }

        return new JNCryptorCipherOutputStream(new JNCryptorMacOutputStream(out, mac), cipher);
    }

    private static SecretKey getKeyForPassword(char[] password, byte[] salt, int iterations, Object provider) throws CryptorException
    {
        try
        {
            SecretKeyFactory factory = null;
            if (provider instanceof Provider)
                factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM, (Provider)provider);
            else if (provider instanceof String)
                factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM, (String)provider);
            else
                factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);

            SecretKey tmp = factory.generateSecret(new PBEKeySpec(password, salt, iterations, AES_256_KEY_SIZE * 8));
            return new SecretKeySpec(tmp.getEncoded(), AES_NAME);
        }
        catch (GeneralSecurityException e) {
            throw new CryptorException(String.format("Failed to generate key from password using %s.",
                                                     KEY_DERIVATION_ALGORITHM), e);
        }
    }

    private AES256JNCryptorOutputStream(JNCryptorCipherOutputStream out)
    {
        super(out);
        
        this.cipherOut = out;
        this.hmacOut = this.cipherOut.getHmacOut();
        this.finalOut = this.hmacOut.getFinalOut();
    }

    /*
     * Common constructor for the password-encrypted cases.  Providers passed as Object so they
     * can be either Provider or String instances.
     */
    private AES256JNCryptorOutputStream(OutputStream out, SecretKey encryptionKey, SecretKey hmacKey,
                                        Object cipherProvider, Object hmacProvider)
    throws CryptorException
    {
        this(getCipherStream(cipherProvider, hmacProvider, out));

        Validate.notNull(encryptionKey, "Encryption key cannot be null.");
        Validate.notNull(hmacKey, "HMac key cannot be null.");

        this.passwordKey = encryptionKey;
        this.hmacKey = hmacKey;
        this.iv = AES256JNCryptor.getSecureRandomData(AES256Ciphertext.AES_BLOCK_SIZE);
        
        initCipher();
    }
    
    
    /**
     * Creates an output stream for key-encrypted data.
     *
     * @param in
     *          the {@code OutputStream} to write the JNCryptor data to
     * @param encryptionKey
     *          the key to encrypt with
     * @param hmacKey
     *          the key to calculate the HMAC with
     * @param cipherProvider
     *          A Provider for the "AES/CBC/PKCS5Padding" Cipher algorithm.  If null, the default Provider is used.
     * @param hmacProvider
     *          A Provider for the "HmacSHA256" Mac algorithm.  If null, the default Provider is used.
     */
    public AES256JNCryptorOutputStream(OutputStream out, SecretKey encryptionKey, SecretKey hmacKey,
                                       Provider cipherProvider, Provider hmacProvider)
    throws CryptorException
    {
        this(out, encryptionKey, hmacKey, (Object)cipherProvider, (Object)hmacProvider);
    }

    /**
     * Creates an output stream for key-encrypted data.
     *
     * @param in
     *          the {@code OutputStream} to write the JNCryptor data to
     * @param encryptionKey
     *          the key to encrypt with
     * @param hmacKey
     *          the key to calculate the HMAC with
     * @param cipherProvider
     *          A registered provider name for the "AES/CBC/PKCS5Padding" Cipher algorithm.  If null, the default is used.
     * @param hmacProvider
     *          A registered provider name for the "HmacSHA256" Mac algorithm.  If null, the default is used.
     */
    public AES256JNCryptorOutputStream(OutputStream out, SecretKey encryptionKey, SecretKey hmacKey,
                                       String cipherProvider, String hmacProvider)
    throws CryptorException
    {
        this(out, encryptionKey, hmacKey, (Object)cipherProvider, (Object)hmacProvider);
    }
    
    /**
     * Creates an output stream for key-encrypted data.
     *
     * @param in
     *          the {@code OutputStream} to write the JNCryptor data to
     * @param encryptionKey
     *          the key to encrypt with
     * @param hmacKey
     *          the key to calculate the HMAC with
     */
    public AES256JNCryptorOutputStream(OutputStream out, SecretKey encryptionKey, SecretKey hmacKey)
    throws CryptorException
    {
        this(out, encryptionKey, hmacKey, (Object)null, null);
    }

    /*
     * Common constructor for the password-encrypted cases.  Providers passed as Object so they
     * can be either Provider or String instances.
     */
    private AES256JNCryptorOutputStream(OutputStream out, char[] password, int iterations,
                                       Object cipherProvider, Object hmacProvider, Object keyProvider)
    throws CryptorException
    {
        this(getCipherStream(cipherProvider, hmacProvider, out));
        
        Validate.notNull(password, "Password cannot be null.");
        Validate.isTrue(password.length > 0, "Password cannot be empty.");

        this.passwordSalt = AES256JNCryptor.getSecureRandomData(AES256JNCryptor.SALT_LENGTH);
        this.passwordKey = getKeyForPassword(password, this.passwordSalt, iterations, keyProvider);

        this.hmacSalt = AES256JNCryptor.getSecureRandomData(AES256JNCryptor.SALT_LENGTH);
        this.hmacKey = getKeyForPassword(password, this.hmacSalt, iterations, keyProvider);

        this.iv = AES256JNCryptor.getSecureRandomData(AES256Ciphertext.AES_BLOCK_SIZE);
        this.iterations = iterations;

        initCipher();
    }

    /**
     * Creates an output stream for password-encrypted data, allowing specification of custom
     * providers for the Cipher, Mac, and SecretKey.
     *
     * @param out
     *          the {@code OutputStream} to write the JNCryptor data to
     * @param password
     *          the password
     * @param iterations
     *          the number of PBKDF iterations to perform
     * @param cipherProvider
     *          A Provider for the "AES/CBC/PKCS5Padding" Cipher algorithm.  If null, the default Provider is used.
     * @param hmacProvider
     *          A Provider for the "HmacSHA256" Mac algorithm.  If null, the default Provider is used.
     * @param keyProvider
     *          A Provider for the "PBKDF2WithHmacSHA1" SecretKey algorithm.  If null, the default Provider is used.
     */
    public AES256JNCryptorOutputStream(OutputStream out, char[] password, int iterations,
                                       Provider cipherProvider, Provider hmacProvider, Provider keyProvider)
    throws CryptorException
    {
        this(out, password, iterations, (Object)cipherProvider, hmacProvider, keyProvider);
    }

    /**
     * Creates an output stream for password-encrypted data, allowing specification of custom
     * providers for the Cipher, Mac, and SecretKey.
     *
     * @param out
     *          the {@code OutputStream} to write the JNCryptor data to
     * @param password
     *          the password
     * @param iterations
     *          the number of PBKDF iterations to perform
     * @param cipherProvider
     *          A registered provider name for the "AES/CBC/PKCS5Padding" Cipher algorithm.  If null, the default is used.
     * @param hmacProvider
     *          A registered provider name for the "HmacSHA256" Mac algorithm.  If null, the default is used.
     * @param keyProvider
     *          A registered provider name for the "PBKDF2WithHmacSHA1" SecretKey algorithm.  If null, the default is used.
     */
    public AES256JNCryptorOutputStream(OutputStream out, char[] password, int iterations,
                                       String cipherProvider, String hmacProvider, String keyProvider)
    throws CryptorException
    {
        this(out, password, iterations, (Object)cipherProvider, hmacProvider, keyProvider);
    }

    /**
     * Creates an output stream for password-encrypted data, using a specific number
     * of PBKDF iterations.
     *
     * @param out
     *          the {@code OutputStream} to write the JNCryptor data to
     * @param password
     *          the password
     * @param iterations
     *          the number of PBKDF iterations to perform
     */
    public AES256JNCryptorOutputStream(OutputStream out, char[] password, int iterations) throws CryptorException
    {
        this(out, password, iterations, (Object)null, null, null);
    }

    /**
     * Creates an output stream for password-encrypted data.
     *
     * @param out
     *          the {@code OutputStream} to write the JNCryptor data to
     * @param password
     *          the password
     */
    public AES256JNCryptorOutputStream(OutputStream out, char[] password) throws CryptorException
    {
        this(out, password, PBKDF_DEFAULT_ITERATIONS);
    }

    
    private void initCipher() throws CryptorException
    {
        try {
            Cipher c = cipherOut.cipher;
            c.init(Cipher.ENCRYPT_MODE, passwordKey, new IvParameterSpec(iv));
            passwordKey = null;
        }
        catch (GeneralSecurityException e) {
            throw new CryptorException("Failed to initialize AES cipher", e);
        }

        try {
            Mac mac = hmacOut.mac;
            mac.init(hmacKey);
            hmacKey = null;
        }
        catch (GeneralSecurityException e) {
            throw new CryptorException("Failed to initialize HMac", e);
        }
    }

    private void writeHeader() throws IOException
    {
        /* Write out the header */
        if (passwordSalt != null)
        {
            hmacOut.write(VERSION);
            hmacOut.write(AES256Ciphertext.FLAG_PASSWORD);
            hmacOut.write(passwordSalt);
            hmacOut.write(hmacSalt);
            hmacOut.write(iv);
        }
        else
        {
            hmacOut.write(VERSION);
            hmacOut.write(0);
            hmacOut.write(iv);
        }
        
        iv = null;
        passwordSalt = null;
        hmacSalt = null;
    }

    public void write(int b) throws IOException
    {
        if (!writtenHeader) {
            writeHeader();
            writtenHeader = true;
        }
        out.write(b);
    }

    public void write(byte[] b, int off, int len) throws IOException
    {
        if (!writtenHeader) {
            writeHeader();
            writtenHeader = true;
        }
        out.write(b, off, len);
    }

    /*
     * A simple subclass to expose access to the Cipher and output stream instances.  Required because access
     * is needed after the super constructor call and this is the easiest way to pass them.
     */
    static class JNCryptorCipherOutputStream extends CipherOutputStream
    {
        Cipher cipher;
        JNCryptorCipherOutputStream(JNCryptorMacOutputStream out, Cipher c)
        {
            super(out, c);
            this.cipher = c;
        }
        
        JNCryptorMacOutputStream getHmacOut() {
            return (JNCryptorMacOutputStream)out;
        }
    }

    /**
     * An output stream to update a Mac object with all bytes passed through, then write the
     * Mac data to the stream upon close to complete the RNCryptor file format.
     */
    static class JNCryptorMacOutputStream extends FilterOutputStream
    {
        Mac mac;
        JNCryptorMacOutputStream(OutputStream out, Mac mac)
        {
            super(out);
            this.mac = mac;
        }
        
        OutputStream getFinalOut() {
            return out;
        }

        public void write(int b) throws IOException
        {
            mac.update((byte)b);
            out.write(b);
        }
        public void write(byte[] b, int off, int len) throws IOException
        {
            mac.update(b, off, len);
            out.write(b, off, len);
        }
        
        public void close() throws IOException
        {
            flush();
            byte[] macData = mac.doFinal();
            out.write(macData);
            out.flush();
            out.close();
        }
    }
}
