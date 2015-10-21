package edu.kit.aifb.eorg.wolfssl;

import java.io.IOException;
import java.io.OutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encapsulates the SSL application output stream for the SSLSocket
 * implementation.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public class WolfSSLAppOutputStream extends OutputStream {

	/**
	 * The SSLSocket implementation.
	 */
	private final WolfSSLSocketImpl sslSocket;
	/**
	 * The logger.
	 */
	private final Logger logger = LoggerFactory.getLogger(WolfSSLAppOutputStream.class);

	/**
	 * Constructor.
	 * 
	 * @param sslSocket
	 *            The SSLSocket implementation.
	 */
	WolfSSLAppOutputStream(WolfSSLSocketImpl sslSocket) {
		this.sslSocket = sslSocket;
	}

	@Override
	public void write(int b) throws IOException {
		if (sslSocket.isClosed() || !sslSocket.isConnected() || sslSocket.isOutputShutdown()) {
			throw new IOException("write to a closed InputStream");
		}

		byte[] onebyte = new byte[1];
		onebyte[0] = (byte) b;
		// Invoke the other write method
		write(onebyte);
	}

	@Override
	public void write(byte[] b) throws IOException {
		if (sslSocket.isClosed() || !sslSocket.isConnected() || sslSocket.isOutputShutdown()) {
			throw new IOException("write to a closed InputStream");
		}
		if (b == null)
			throw new NullPointerException();

		sslSocket.write(b, b.length);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		if (sslSocket.isClosed() || !sslSocket.isConnected() || sslSocket.isOutputShutdown()) {
			throw new IOException("write to a closed InputStream");
		}
		// Check the input
		if (b == null) {
			throw new NullPointerException();
		} else if (off < 0 || len < 0 || len > b.length - off) {
			throw new IndexOutOfBoundsException();
		} else if (len == 0) {
			return;
		}

		if (logger.isDebugEnabled())
			logger.debug("Write b={}, off={}, len={}.", b, off, len);

		byte[] b2 = new byte[len];
		sslSocket.write(b2, len);

		System.arraycopy(b2, 0, b, off, len);
	}

	@Override
	public void flush() throws IOException {
		if (logger.isDebugEnabled())
			logger.debug("flush()");

		// sslSocket.flush();
	}

	@Override
	public void close() throws IOException {
		if (logger.isDebugEnabled())
			logger.debug("close()");

		sslSocket.close();
	}
}
