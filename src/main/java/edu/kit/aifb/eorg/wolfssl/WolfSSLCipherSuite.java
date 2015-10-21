package edu.kit.aifb.eorg.wolfssl;

/**
 * The TLS cipher suite values of wolfSSL and JSSE.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
class WolfSSLCipherSuite {

	/**
	 * The JSSE cipher suite string.
	 */
	final String javaString;
	/**
	 * The wolfSSL cipher suite string.
	 */
	final String wolfSSLString;

	/**
	 * The constructor.
	 * 
	 * @param javaString
	 *            The JSSE cipher suite string.
	 * @param openSSLString
	 *            The wolfSSL cipher suite string.
	 */
	public WolfSSLCipherSuite(String javaString, String openSSLString) {
		this.javaString = javaString;
		this.wolfSSLString = openSSLString;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null)
			return false;
		if (obj == this)
			return true;
		if (!(obj instanceof WolfSSLCipherSuite))
			return false;

		WolfSSLCipherSuite other = (WolfSSLCipherSuite) obj;
		return this.javaString.equals(other.javaString) && this.wolfSSLString.equals(other.wolfSSLString);
	}
}