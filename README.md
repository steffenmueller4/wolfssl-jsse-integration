# wolfssl-jsse-integration
A JSSE API integration of wolfssl / wolfssl-jni (http://www.wolfssl.com)

Please do not use this project in production use, as it is a research prototype!!!

Installation steps:
1. Clone the repository
2. Follow the wolfSSL manual to install the JNI library (http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf). 
   Therefore, compile and install wolfSSL. We build our library using wolfSSL 3.6.9.
   Afterward, compile and install the wolfSSL JNI library (version 1.2.0). You only have to build the native library 
   using the "java.sh" script file. You do not need to build the corresponding JAR file with ANT, as we have build 
   it and put it into the "lib" directory (lib/wolfssl-3.6.9.jar).
3. Install the Maven dependencies (wolfssl-3.6.9.jar).
   For this, go to the source base directory and run:
   mvn install:install-file -Dfile=lib/wolfssl-3.6.9.jar -DpomFile=lib/wolfssl-3.6.9.pom
4. Now, you can build the JSSE integration library:
   mvn package -Dmaven.test.skip=true


To use the JSSE integration:
1. Install the security provider. For example, within a Java project you can do it this way:
   java.security.Security.insertProviderAt(new edu.kit.aifb.eorg.wolfssl.WolfSSLJSSEProvider(), 1);
   
   Other installation options are described at: http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#ProviderInstalling
2. Afterward, you can use the library in the old-fashioned Java way:
   SSLContext ctx = SSLContext.getDefault;
   SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(...);
   
   However, you have to set the path to JNI native library and the keyStore as well as the trustStore, when starting the Java project:
   -Djava.library.path=<path_to_the_wolfssl_JNI_library> \
   -Djavax.net.ssl.keyStore=<path_to_the_wolfssl_JNI_library_source_directory>/examples/certs/server-key.pem \
   -Djavax.net.ssl.trustStore=<path_to_the_wolfssl_JNI_library_source_directory>/examples/certs/server-cert.pem
