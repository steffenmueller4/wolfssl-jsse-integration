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
	 * The private key file, must be of type DER or PEM, default is PEM.
	 */
	private String privateKeyFile;
	/**
	 * The file format of the private key file (DER or PEM).
	 */
	private KeystoreType privateKeyFileFormat = KeystoreType.PEM;
	/**
	 * Certification authority file that is used to invoke the
	 * wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX *ctx, const char *CAfile,
	 * const char *CApath) function.
	 */
	private String caFile;
	/**
	 * Certificate file that is used to invoke the
	 * wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX *ctx, const char *CAfile,
	 * int type) function.
	 */
	private String certificateFile;
	/**
	 * The certificate file format.
	 */
	private KeystoreType certificateFileFormat = KeystoreType.PEM;
	/**
	 * Certificate chain file that is used to invoke the
	 * wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX *ctx, const char
	 * *file) function.
	 */
	private String certificateChainFile;
	private static boolean printedWarnings = false;

	static {
		defaultServerSSLParams = new SSLParameters();
		defaultServerSSLParams.setProtocols(new String[] { Constants.TLS_VERSION_12 });
		defaultServerSSLParams.setCipherSuites(WolfSSLCipherSuiteList.getJavaCipherSuiteList());

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

		if (printedWarnings) {
			logger.warn(
					"DO NOT USE THIS LIBRARY IN PRODUCTION ENVIRONMENTS!!! THIS LIBRARY COULD CONTAIN SECURITY ISSUES!!!");
		}

		printedWarnings = true;
		logger.debug("WolfSSL Environment created.");
	}

	@Override
	protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
		// Initialize debugging
		if (logger.isDebugEnabled()) {
			int ret = WolfSSL.debuggingON();
			if (ret == WolfSSL.SSL_SUCCESS) {
				logger.debug("Debug logging enabled.");
			} else if (ret == WolfSSL.NOT_COMPILED_IN)
				logger.debug("WolfSSL has been compiled without debug logging.");
			else
				logger.error("Could not enable debug logging!");
		}
		// Initialize logging
		if (logger.isDebugEnabled() || logger.isInfoEnabled()) {
			loggingCallback = new LoggingCallback();
			WolfSSL.setLoggingCb(loggingCallback);
		}

		// Get the keystore and truststore
		privateKeyFile = System.getProperty(Constants.COM_WOLFSSL_PRIVATE_KEY_FILE_PROPERTY);
		caFile = System.getProperty(Constants.COM_WOLFSSL_VERIFY_LOCATIONS_PROPERTY);
		certificateFile = System.getProperty(Constants.COM_WOLFSSL_CERTIFICATE_FILE_PROPERTY);
		certificateChainFile = System.getProperty(Constants.COM_WOLFSSL_CERTIFICATE_CHAIN_FILE_PROPERTY);

		// The private key file must be set!
		if (privateKeyFile == null || privateKeyFile.isEmpty())
			throw new KeyManagementException(
					"Private key file must be specified via '" + Constants.COM_WOLFSSL_PRIVATE_KEY_FILE_PROPERTY + "'");

		// Either the certificate file or the certificate chain file must be
		// set!
		if ((certificateFile == null || certificateFile.isEmpty())
				&& (certificateChainFile == null || certificateChainFile.isEmpty()))
			throw new KeyManagementException("Either the certificate file property ('"
					+ Constants.COM_WOLFSSL_CERTIFICATE_FILE_PROPERTY + "') or the certificate chain file property ('"
					+ Constants.COM_WOLFSSL_CERTIFICATE_CHAIN_FILE_PROPERTY + "') must be set!");

		// Check the file extension of the private key file
		if (privateKeyFile.endsWith(Constants.DER_FILE_EXTENSION))
			privateKeyFileFormat = KeystoreType.DER;

		// Check the file extension of the certificate file
		if (certificateFile != null && certificateFile.endsWith(Constants.DER_FILE_EXTENSION))
			certificateFileFormat = KeystoreType.DER;

		// Check the file extension of the certificate chain file; must be a
		// .pem file
		if (certificateChainFile != null && certificateChainFile.endsWith(Constants.DER_FILE_EXTENSION))
			throw new KeyManagementException("Certificate chain file specified by '"
					+ Constants.COM_WOLFSSL_CERTIFICATE_CHAIN_FILE_PROPERTY + "' must be a .pem file!");

		// Check the file extension of the ca file; must be a .pem file
		if (caFile != null && caFile.endsWith(Constants.DER_FILE_EXTENSION))
			throw new KeyManagementException("Certification authority file specified by '"
					+ Constants.COM_WOLFSSL_VERIFY_LOCATIONS_PROPERTY + "' must be a .pem file!");

		// Check assertions
		assert (privateKeyFile != null && !privateKeyFile.isEmpty());
		assert ((certificateFile != null && !certificateFile.isEmpty())
				|| (certificateChainFile != null && !certificateChainFile.isEmpty()));

		logger.debug("engineInit(...) complete");

		isInitialized = true;
	}

	@Override
	protected SSLSocketFactory engineGetSocketFactory() {
		if (!isInitialized) {
			throw new IllegalStateException("Context is not initialized!");
		}

		assert (isInitialized);
		assert (privateKeyFile != null && !privateKeyFile.isEmpty());
		assert ((certificateFile != null && !certificateFile.isEmpty())
				|| (certificateChainFile != null && !certificateChainFile.isEmpty()));

		try {
			// create the context, where we only allow TLSv1.2
			WolfSSLContext context = initContext(new WolfSSLContext(WolfSSL.TLSv1_2_ClientMethod()));

			logger.debug("engineGetSocketFactory() complete. Creating a socket factory now.");

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

		assert (isInitialized);
		assert (privateKeyFile != null && !privateKeyFile.isEmpty());
		assert ((certificateFile != null && !certificateFile.isEmpty())
				|| (certificateChainFile != null && !certificateChainFile.isEmpty()));

		/* Load Server key and certificate */
		try {
			WolfSSLContext context = initContext(new WolfSSLContext(WolfSSL.TLSv1_2_ServerMethod()));

			logger.debug("engineGetServerSocketFactory() complete. Creating a server socket factory now.");

			return new WolfSSLServerSocketFactoryImpl(context);
		} catch (Exception e) {
			logger.error("Could not return server socket factory!", e);
			throw new IllegalStateException("Context is not initialized!");
		}
	}

	private WolfSSLContext initContext(WolfSSLContext context) throws KeyManagementException {
		// Disable Certificate Revocation List (CRL) feature
		// TODO: Fix it
		int ret = context.disableCRL();
		if (ret != WolfSSL.SSL_SUCCESS) {
			throw new KeyManagementException("failed to disable certificate revocation list!");
		}
		logger.warn("Certificate Revocation List (CRL) feature is disabled, as this is a research prototype!");

		// load certificate files
		if (certificateChainFile != null) {
			ret = context.useCertificateChainFile(certificateFile);
		} else {
			ret = context.useCertificateFile(certificateFile, certificateFileFormat.toValue());
		}
		if (ret != WolfSSL.SSL_SUCCESS) {
			throw new KeyManagementException("failed to load client certificate!");
		}

		// Load the private key file
		ret = context.usePrivateKeyFile(privateKeyFile, privateKeyFileFormat.toValue());
		if (ret != WolfSSL.SSL_SUCCESS) {
			throw new KeyManagementException("failed to load private key!");
		}

		// if the certification authority file is provided, load the file
		if (caFile != null) {
			context.loadVerifyLocations(caFile, null);
			if (ret != WolfSSL.SSL_SUCCESS) {
				throw new KeyManagementException("failed to load verify locations!");
			}
		}
		// Set verify callback to No Verification (Default)
		// TODO: Fix it
		context.setVerify(WolfSSL.SSL_VERIFY_NONE, null);
		logger.warn("Verification mode for peer certificates is always disabled, as this is a research prototype!");

		return context;
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
