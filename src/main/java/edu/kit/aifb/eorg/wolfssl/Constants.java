package edu.kit.aifb.eorg.wolfssl;

/**
 * Encapsulates used constants of this package.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
class Constants {

	/**
	 * TLS version 1.2 constant.
	 */
	public static final String TLS_VERSION_12 = "TLSv1.2";
	/**
	 * Context name.
	 */
	public static final String SSL_CONTEXT_IMPL = WolfSSLContextImpl.class.getName();
	/**
	 * System environment variable for the
	 * wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX *ctx, const char *CAfile,
	 * int type) function.
	 */
	public static final String COM_WOLFSSL_CERTIFICATE_FILE_PROPERTY = "com.wolfssl.certificateFile";
	/**
	 * System environment variable for the
	 * wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX *ctx, const char
	 * *file) function.
	 */
	public static final String COM_WOLFSSL_CERTIFICATE_CHAIN_FILE_PROPERTY = "com.wolfssl.certificateChainFile";
	/**
	 * System environment variable for the
	 * wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX *ctx, const char *keyFile,
	 * int type) function.
	 */
	public static final String COM_WOLFSSL_PRIVATE_KEY_FILE_PROPERTY = "com.wolfssl.privateKeyFile";
	/**
	 * System environment variable for the
	 * wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX *ctx, const char *CAfile,
	 * const char *CApath) function.
	 */
	public static final String COM_WOLFSSL_VERIFY_LOCATIONS_PROPERTY = "com.wolfssl.certificateAuthorityFile";
	/**
	 * The default value for backlog.
	 */
	public static final int BACKLOG_DEFAULT = 50;
	/**
	 * The .der file extension for binary certificate/private key files.
	 */
	public static final String DER_FILE_EXTENSION = ".der";

	/**
	 * Private constructor.
	 */
	private Constants() {

	}
}
