JNCryptor 
========

JNCryptor is an easy-to-use library for encrypting data with AES. It was ported to Java from the [RNCryptor](https://github.com/rnapier/RNCryptor) library for iOS.

Getting JNCryptor
-----------------

You can download binaries, documentation and source from the Releases page.  Maven users can copy the following snippet to retrieve the artifacts from Maven Central:

```xml
<dependency>
    <groupId>org.cryptonode.jncryptor</groupId>
    <artifactId>jncryptor</artifactId>
    <version>1.0.0</version>
</dependency>
````

The Javadocs can also be browsed online (TODO).

Using JNCryptor
----------------

A quick example is shown below:

```java
JNCryptor cryptor = new AES256JNCryptor();
byte[] plaintext = "Hello, World!".getBytes();
String password = "secretsquirrel";

try {
  byte[] ciphertext = cryptor.encryptData(plaintext, password.toCharArray());
} catch (CryptorException e) {
  // Something went wrong
  e.printStackTrace();
}
```

Iterations
----------

JNCryptor supports changing the number of PBKDF2 iterations performed by the library. I regret introducing this functionality for two reasons:

* It is a lazy effort to try and improve performance on Android devices at the expense of security. Really I need to benchmark the library and determine where the slow points are.

* There is no support in the data format for expressing the number of iterations, therefore you must store this value outside the data itself. Other implementations may not support this feature, causing compatibility problems.

In summary - consider ignoring this feature until the data format supports it. Hopefully I'll improve performance in other ways before that.

Android
-------

JNCryptor can be used in Android applications. Download the latest binary release and place the JAR in the `libs` folder for your project.

Please note that very little Android testing has been completed and some users report compatibility problems with old versions of Android (see the Issues page). If I can find an easy way to do so, I'll start increasing my Android testing and improve the library accordingly. 


Data Format
------------

A proprietary data format is used that stores the IV, salt values (if applicable), ciphertext and HMAC value in a compact fashion. Methods are offered to encrypt data based on either an existing key, or a password. In the latter case, a key is derived from the password using a key derivation function, with 10,000 iterations and a salt valu.e

See [the spec documents online](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md).

Keys are derived from the password and the appropriate salt value using the PBKDF2 function with SHA1. A separate key is generated for encrypting the plaintext and computing the HMAC.

History
--------

The data format supported by this library is v3. Both v1 and v0 have a [significant security flaw](http://robnapier.net/blog/rncryptor-hmac-vulnerability-827) whereby only the ciphertext was included in the HMAC value. There are no plans to support v1 or v0. v2 was deprecated due to a multi-byte password issue discovered in the objective-c implementation.
