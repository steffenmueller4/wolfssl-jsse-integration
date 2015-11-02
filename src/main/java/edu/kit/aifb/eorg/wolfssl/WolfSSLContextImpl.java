package edu.kit.aifb.eorg.wolfssl;

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;

/**
 * The JSSE API SSLContext implementation.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public final class WolfSSLContextImpl extends SSLContextSpi {

	private enum KeystoreType {
		DER(WolfSSL.SSL_FILETYPE_ASN1), PEM(WolfSSL.SSL_FILETYPE_PEM);

		KeystoreType(int v) {
			this.v = v;
		}

		final int v;

		public int toValue() {
			return v;
		}
	}

	/**
	 * The default SSL parameters.
	 */
	static final SSLParameters defaultServerSSLParams;
	/**
	 * Holds a thrown exception from static methods, if an exception occured.
	 */
	private static Exception thrown;
	/**
	 * The logger.
	 */
	private final Logger logger = LoggerFactory.getLogger(WolfSSLContextImpl.class);
	/**
	 * Indicates whether the JSSE SSLContext is initialized.
	 */
	private boolean isInitialized;
	/**
	 * The debug logging callback.
	 */
	private LoggingCallback loggingCallback;
	/**
	 * The wolfSSL instance.
	 */
	@SuppressWarnings("unused")
	private static WolfSSL sslLib;
	/**
	 * The keystore file, must be of type DER or PEM, default is PEM.
	 */
	private String keystoreFile;
	/**
	 * The file format of the keystore (DER or PEM).
	 */
	private KeystoreType keystoreFileFormat = KeystoreType.PEM;
	/**
	 * The optional keystore password.
	 */
	@SuppressWarnings("unused")
	private String keystorePassword;
	/**
	 * The truststore file, must be of type DER or PEM, default is PEM.
	 */
	private String truststoreFile;
	/**
	 * The file format of the truststore (DER or PEM).
	 */
	private KeystoreType truststoreFileFormat = KeystoreType.PEM;
	/**
	 * The optional truststore password.
	 */
	@SuppressWarnings("unused")
	private String truststorePassword;

	static {
		defaultServerSSLParams = new SSLParameters();
		defaultServerSSLParams.setProtocols(new String[] { Constants.TLS_VERSION_12 });
		defaultServerSSLParams.setCipherSuites(new String[]{"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"});

		try {
			System.out.println("Loading wolfSSL library...");

			try {
				System.loadLibrary("wolfSSL");

				/* init library */
				sslLib = new WolfSSL();
			} catch (Throwable e) {
				System.out.println("Exception occured: " + e.getMessage());
				throw new Exception(e);
			}

			System.out.println("WolfSSL successfully initialized.");
		} catch (Exception e) {
			thrown = (Exception) e;
		}
	}

	public WolfSSLContextImpl() throws Exception {
		if (thrown != null)
			throw thrown;

		engineInit(null, null, null);

		logger.info("WolfSSL Environment created.");
		logger.warn("DO NOT USE THIS LIBRARY IN PRODUCTION ENVIRONMENTS!!!");
	}

	@Override
	protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
		// Initialize logging and debugging
		if (logger.isInfoEnabled()) {
			int ret = WolfSSL.debuggingON();
			if (ret == WolfSSL.SSL_SUCCESS) {
				logger.info("Debug logging enabled.");
			} else if (ret == WolfSSL.NOT_COMPILED_IN)
				logger.info("WolfSSL has been compiled without debug logging.");
			else
				logger.error("Could not enable debug logging!");
			
			loggingCallback = new LoggingCallback();
			WolfSSL.setLoggingCb(loggingCallback);
		}

		// Get the keystore and truststore
		keystoreFile = System.getProperty(Constants.JAVAX_NET_SSL_KEY_STORE);
		keystorePassword = System.getProperty(Constants.JAVAX_NET_SSL_KEY_STORE_PASSWORD);
		truststoreFile = System.getProperty(Constants.JAVAX_NET_SSL_TRUST_STORE);
		truststorePassword = System.getProperty(Constants.JAVAX_NET_SSL_TRUST_STORE_PASSWORD);

		if (keystoreFile == null || keystoreFile.isEmpty())
			throw new KeyManagementException(
					"Keystore must be specified via '" + Constants.JAVAX_NET_SSL_KEY_STORE + "'");
		if (truststoreFile == null || truststoreFile.isEmpty())
			throw new KeyManagementException(
					"Truststore must be specified via '" + Constants.JAVAX_NET_SSL_TRUST_STORE + "'");

		if (keystoreFile.endsWith(".der"))
			keystoreFileFormat = KeystoreType.DER;
		if (truststoreFile.endsWith(".der"))
			truststoreFileFormat = KeystoreType.DER;

		assert (keystoreFile != null && !keystoreFile.isEmpty());
		assert (truststoreFile != null && !truststoreFile.isEmpty());

		logger.info("engineInit(...) complete");

		isInitialized = true;
	}

	@Override
	protected SSLSocketFactory engineGetSocketFactory() {
		if (!isInitialized) {
			throw new IllegalStateException("Context is not initialized!");
		}

		assert (keystoreFile != null && !keystoreFile.isEmpty());
		assert (truststoreFile != null && !truststoreFile.isEmpty());

		try {
			// create the context, where we only allow TLSv1.2
			WolfSSLContext context = new WolfSSLContext(WolfSSL.TLSv1_2_ClientMethod());
			/* load certificate files */
			int ret = context.useCertificateFile(truststoreFile, truststoreFileFormat.toValue());
			if (ret != WolfSSL.SSL_SUCCESS) {
				throw new KeyManagementException("failed to load client certificate!");
			}

			ret = context.usePrivateKeyFile(keystoreFile, keystoreFileFormat.toValue());
			if (ret != WolfSSL.SSL_SUCCESS) {
				throw new KeyManagementException("Failed to load private key!");
			}

			// Set verify callback to No Verification (Default)
			context.setVerify(WolfSSL.SSL_VERIFY_NONE, null);

			return new WolfSSLSocketFactoryImpl(context);
		} catch (Exception e) {
			logger.error("Could not return socket factory!", e);
			throw new IllegalStateException("Context is not initialized!");
		}
	}

	@Override
	protected SSLServerSocketFactory engineGetServerSocketFactory() {
		if (!isInitialized) {
			throw new IllegalStateException("Context is not initialized!");
		}
		/* Load Server key and certificate */
		try {
			WolfSSLContext context = new WolfSSLContext(WolfSSL.TLSv1_2_ServerMethod());

			/* load certificate files */
			int ret = context.useCertificateFile(truststoreFile, truststoreFileFormat.toValue());
			if (ret != WolfSSL.SSL_SUCCESS) {
				throw new KeyManagementException("failed to load client certificate!");
			}

			ret = context.usePrivateKeyFile(keystoreFile, keystoreFileFormat.toValue());
			if (ret != WolfSSL.SSL_SUCCESS) {
				throw new KeyManagementException("failed to load client private key!");
			}

			// Set verify callback to No Verification (Default)
			context.setVerify(WolfSSL.SSL_VERIFY_NONE, null);

			return new WolfSSLServerSocketFactoryImpl(context);
		} catch (Exception e) {
			logger.error("Could not return server socket factory!", e);
			throw new IllegalStateException("Context is not initialized!");
		}
	}

	@Override
	protected SSLEngine engineCreateSSLEngine() {
		logger.error("Method 'engineCreateSSLEngine()' not yet implemented!");
		return null;
	}

	@Override
	protected SSLEngine engineCreateSSLEngine(String host, int port) {
		logger.error("Method 'engineCreateSSLEngine(String host, int port)' not yet implemented!");
		return null;
	}

	@Override
	protected SSLSessionContext engineGetServerSessionContext() {
		logger.error("Method 'engineGetServerSessionContext()' not yet implemented!");
		return null;
	}

	@Override
	protected SSLSessionContext engineGetClientSessionContext() {
		logger.error("Method 'engineGetClientSessionContext()' not yet implemented!");
		return null;
	}

	@Override
	protected SSLParameters engineGetDefaultSSLParameters() {
		return defaultServerSSLParams;
	}
}
