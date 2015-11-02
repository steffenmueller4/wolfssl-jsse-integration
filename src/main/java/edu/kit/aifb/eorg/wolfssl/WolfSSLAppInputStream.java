package edu.kit.aifb.eorg.wolfssl;

import java.io.IOException;
import java.io.InputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encapsulates the SSL application input stream for the SSLSocket
 * implementation.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public class WolfSSLAppInputStream extends InputStream {

	/**
	 * A byte array with the length = 1.
	 */
	private final byte[] oneByte = new byte[1];
	/**
	 * The SSLSocket implementation.
	 */
	private final WolfSSLSocketImpl sslSocket;
	/**
	 * The logger.
	 */
	private final Logger logger = LoggerFactory.getLogger(WolfSSLAppInputStream.class);

	/**
	 * Constructor.
	 * 
	 * @param sslSocket
	 *            The SSLSocket implementation.
	 */
	WolfSSLAppInputStream(WolfSSLSocketImpl sslSocket) {
		this.sslSocket = sslSocket;
	}

	@Override
	public int read() throws IOException {
		if (sslSocket.isClosed() || !sslSocket.isConnected() || sslSocket.isInputShutdown()) {
			throw new IOException("read on a closed InputStream");
		}

		// Invoke the other read method
		int n = sslSocket.read(oneByte, 1);
		if (n <= 0) {
			// EOF
			return -1;
		}
		return oneByte[0] & 0xff;
	}

	@Override
	public int available() throws IOException {
		if (sslSocket.isClosed() || !sslSocket.isConnected() || sslSocket.isInputShutdown()) {
			throw new IOException("available on a closed InputStream");
		}

		// As we have no chance to get any other value, return 0
		int a = 0;

		if (logger.isDebugEnabled())
			logger.debug("{} bytes available.", a);

		return a;
	}

	@Override
	public void close() throws IOException {
		if (logger.isDebugEnabled())
			logger.debug("close()");

		sslSocket.close();
	}

	@Override
	public synchronized void mark(int readlimit) {
		// Do nothing, as mark is not supported.
	}

	@Override
	public synchronized void reset() throws IOException {
		throw new IOException("mark/reset not supported");
	}

	@Override
	public boolean markSupported() {
		return false;
	}
}
