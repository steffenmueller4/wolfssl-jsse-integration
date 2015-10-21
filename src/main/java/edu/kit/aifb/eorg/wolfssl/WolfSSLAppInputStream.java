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
		int n = read(oneByte);
		if (n <= 0) {
			// EOF
			return -1;
		}
		return oneByte[0] & 0xff;
	}

	@Override
	public int read(byte[] b) throws IOException {
		if (sslSocket.isClosed() || !sslSocket.isConnected() || sslSocket.isInputShutdown()) {
			throw new IOException("read on a closed InputStream");
		}

		// Invoke the other read method
		return sslSocket.read(b, b.length);
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (sslSocket.isClosed() || !sslSocket.isConnected() || sslSocket.isInputShutdown()) {
			throw new IOException("read on a closed InputStream");
		}

		// Check the input
		if (b == null) {
			throw new NullPointerException();
		} else if (off < 0 || len < 0 || len > b.length - off) {
			throw new IndexOutOfBoundsException();
		} else if (len == 0) {
			return 0;
		}

		// Check assertions
		assert len > 0 && b.length > 0 && off >= 0 && (off + len) <= b.length;

		// Read the bytes from the byte buffer in the socket impl
		byte[] b2 = new byte[len];
		int r = read(b2);

		System.arraycopy(b2, 0, b, off, len);

		if (logger.isDebugEnabled())
			logger.debug("Read bytes b={}, off={}, len={}.", b, off, len);

		return r;
	}

	@Override
	public long skip(long n) throws IOException {
		if (sslSocket.isClosed() || !sslSocket.isConnected() || sslSocket.isInputShutdown()) {
			throw new IOException("skip on a closed InputStream");
		}

		// Check the input
		if (n <= 0) {
			return 0;
		}

		if (logger.isDebugEnabled())
			logger.debug("Skipping {} bytes.", n);

		int nInt = (int) n;
		byte[] b = new byte[nInt];
		return sslSocket.read(b, nInt);
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
