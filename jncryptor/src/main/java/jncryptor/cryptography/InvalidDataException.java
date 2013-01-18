package jncryptor.cryptography;

/**
 * 
 */
class InvalidDataException extends Exception {

  private static final long serialVersionUID = 1L;

  /**
   * 
   */
  public InvalidDataException() {
  }

  /**
   * @param message
   */
  public InvalidDataException(String message) {
    super(message);
  }

  /**
   * @param cause
   */
  public InvalidDataException(Throwable cause) {
    super(cause);
  }

  /**
   * @param message
   * @param cause
   */
  public InvalidDataException(String message, Throwable cause) {
    super(message, cause);   
  }
}
