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
	 * A byte array with the length = 1.
	 */
	private final byte[] oneByte = new byte[1];

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

		// Put the int into the byte array
		oneByte[0] = (byte) b;

		// Write to the sslSocket
		sslSocket.write(oneByte, 1);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		if (b == null)
			throw new NullPointerException("b");
		else if (off < 0 || len < 0 || len > b.length - off) {
			throw new IndexOutOfBoundsException();
		} else if (len == 0) {
			return;
		}

		if(off == 0){
			sslSocket.write(b, len);
		}else{
			byte[] b2 = new byte[len];
			System.arraycopy(b, off, b2, 0, len);
			
			sslSocket.write(b2, len);
		}
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
