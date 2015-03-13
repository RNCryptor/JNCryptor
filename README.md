JNCryptor 
========

JNCryptor is an easy-to-use library for encrypting data with AES. It was ported to Java from the [RNCryptor](https://github.com/RNCryptor/RNCryptor) library for iOS.

Android Assistance Needed
-------------------------

JNCryptor was originally written for use in a standard Java environment, but more and more people are using it on the Android platform. This makes sense, since RNCryptor was designed for use on iOS. It is well overdue for Android to receive more love as a target platform. Specifically, the following tasks are required:

- Address the security vulnerability affecting Android < 4.4 (see [Issue #25](https://github.com/RNCryptor/JNCryptor/issues/25)).
 - Improve performance by implementing critical parts of the code natively.
 - Thoroughly test more Android versions and try to adjust the code to support older editions.
 
It will probably be necessary to create a separate branch for this, or perhaps even a fresh project. Since Android is not a platform I'm familiar with, I'd like to invite interested parties to get involved to help with this.

Please send me an email if interested, my details are in my GitHub profile.

Getting JNCryptor
-----------------

The Javadocs can be browsed online: [JNCryptor Javadocs](http://rncryptor.github.io/JNCryptor/javadoc/).

You can download binaries, documentation and source from the Releases page.  Maven users can copy the following snippet to retrieve the artifacts from Maven Central:

```xml
<dependency>
    <groupId>org.cryptonode.jncryptor</groupId>
    <artifactId>jncryptor</artifactId>
    <version>1.2.0</version>
</dependency>
````



News
----

Follow [@JNCryptor](https://twitter.com/JNCryptor) for notifications of releases.


| Date        | News           | 
| ------------- | ------------- | 
| 2014-10-05      | Version 1.2.0 released. Exposes an encryption method that takes salt and IV values. Adds support for caching encryption keys.  |
| 2014-08-23      | Version 1.1.0 released. Adds support for streaming operations, plus constant time HMAC calculation. Apache Commons IO is no longer a dependency.  |
| 2014-01-19      | Version 1.0.1 released. Fixes issue #4, which caused the wrong version number to be output in some situations.  |
| 2014-01-13      | Version 1.0.0 released. This version is more streamlined, with no external dependencies. The previously deprecated factory classes are now removed.  |
| 2014-01-13      | Projected moved to GitHub. |
| 2014-01-07      | Version 0.5 released. This version supports v3 of the RNCryptor format, which was necessary due to a bug in the objective-c implementation (see [original issue here](https://github.com/rnapier/RNCryptor/issues/77)). This new version of JNCryptor deprecates the factory-style method of creating instances in favour of a new class, `AES256JNCryptor`. See the documentation for more details. | 
| 2013-12-27      | Version 0.4 released. Now the number of PBKDF iterations can be set. Note: read the caution below before considering using variable iterations.      | 
| 2013-02-28 | Version 0.3 released. Fixes an issue where spaces in the path to the JAR caused the factory to fail.      | 
| 2013-02-03 | Version 0.2 released. No functionality changes, however the dependencies are now correctly contained in the binary downloads.      |
| 2013-01-31 | Version 0.1 released.      |






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

JNCryptor supports changing the number of PBKDF2 iterations performed by the library. Unfortunately, the number of iterations is not currently encoded in the data format, which means that both sides of the conversation need to know how many iterations have been used.

There are plans afoot to include the ieration count in the data format (hopefully in v4). Until that time, use these feature with caution.


Android
-------
> **IMPORTANT**: Due to a bug in the Android SecureRandom implementation, JNCryptor is not currently safe to use in Android versions prior to 4.4. Please see [an announcement from Google](http://android-developers.blogspot.co.uk/2013/08/some-securerandom-thoughts.html) from back in 2013. The issue is tracked here as [Issue #25](https://github.com/RNCryptor/JNCryptor/issues/25).

 
JNCryptor can be used in Android applications, v2.3.3 (Android 10) and above. Download the latest binary release and place the JAR in the `libs` folder for your project.

Please note that very little Android testing has been completed and some users report compatibility problems with old versions of Android (see the Issues page). If I can find an easy way to do so, I'll start increasing my Android testing and improve the library accordingly. 


Data Format
------------

A proprietary data format is used that stores the IV, salt values (if applicable), ciphertext and HMAC value in a compact fashion. Methods are offered to encrypt data based on either an existing key, or a password. In the latter case, a key is derived from the password using a key derivation function, with 10,000 iterations and a salt valu.e

See [the spec documents online](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md).

Keys are derived from the password and the appropriate salt value using the PBKDF2 function with SHA1. A separate key is generated for encrypting the plaintext and computing the HMAC.

History
--------

The data format supported by this library is v3. Both v1 and v0 have a [significant security flaw](http://robnapier.net/blog/rncryptor-hmac-vulnerability-827) whereby only the ciphertext was included in the HMAC value. There are no plans to support v1 or v0. v2 was deprecated due to a multi-byte password issue discovered in the objective-c implementation.
