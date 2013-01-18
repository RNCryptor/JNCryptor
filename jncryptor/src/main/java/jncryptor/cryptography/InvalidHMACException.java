package jncryptor.cryptography;

/**
 * 
 */
public class InvalidHMACException extends CryptorException {

  private static final long serialVersionUID = 1L;

  /**
   * 
   */
  public InvalidHMACException() {
  }

  /**
   * @param message
   */
  public InvalidHMACException(String message) {
    super(message);
  }

  /**
   * @param cause
   */
  public InvalidHMACException(Throwable cause) {
    super(cause);
  }

  /**
   * @param message
   * @param cause
   */
  public InvalidHMACException(String message, Throwable cause) {
    super(message, cause);
  }

}
