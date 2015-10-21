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
	 * System environment variable for the trust store password.
	 */
	public static final String JAVAX_NET_SSL_TRUST_STORE_PASSWORD = "javax.net.ssl.trustStorePassword";
	/**
	 * System environment variable for the key store password.
	 */
	public static final String JAVAX_NET_SSL_KEY_STORE_PASSWORD = "javax.net.ssl.keyStorePassword";
	/**
	 * System environment variable for the trust store.
	 */
	public static final String JAVAX_NET_SSL_TRUST_STORE = "javax.net.ssl.trustStore";
	/**
	 * System environment variable for the key store.
	 */
	public static final String JAVAX_NET_SSL_KEY_STORE = "javax.net.ssl.keyStore";

	/**
	 * Private constructor.
	 */
	private Constants() {

	}
}
