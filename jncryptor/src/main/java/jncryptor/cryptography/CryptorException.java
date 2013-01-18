package jncryptor.cryptography;

/**
 * An exception thrown when an error occurs encrypting or decrypting.
 */
public class CryptorException extends Exception {

  private static final long serialVersionUID = 1L;

  /**
   * 
   */
  public CryptorException() {
    // TODO Auto-generated constructor stub
  }

  /**
   * @param message
   */
  public CryptorException(String message) {
    super(message);
    // TODO Auto-generated constructor stub
  }

  /**
   * @param cause
   */
  public CryptorException(Throwable cause) {
    super(cause);
    // TODO Auto-generated constructor stub
  }

  /**
   * @param message
   * @param cause
   */
  public CryptorException(String message, Throwable cause) {
    super(message, cause);
    // TODO Auto-generated constructor stub
  }

}
