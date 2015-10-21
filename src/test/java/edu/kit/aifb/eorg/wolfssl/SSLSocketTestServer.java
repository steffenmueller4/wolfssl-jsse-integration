package edu.kit.aifb.eorg.wolfssl;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

/**
 * Provides a basic server for the tests.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
abstract class SSLSocketTestServer extends SSLSocketBaseClientServer {

	/**
	 * The server socket.
	 */
	protected SSLServerSocket sslServerSocket;

	/**
	 * Constructor.
	 * 
	 * @param stopOnException
	 *            Indicates if the test should stop on an exception.
	 * @param registerHandshakeCompletedListener
	 *            Indicates if a HandshakeCompletedListener should be
	 *            registered.
	 * @throws NoSuchAlgorithmException
	 *             If the SSLContext could not be instantiated.
	 */
	public SSLSocketTestServer(int port, boolean stopOnException,
			boolean registerHandshakeCompletedListener)
			throws NoSuchAlgorithmException {
		super("Server", port, stopOnException, registerHandshakeCompletedListener);
	}

	@Override
	public void startup() throws IOException {
		SSLServerSocketFactory sslssf = (SSLServerSocketFactory) sslContext
				.getServerSocketFactory();
		sslServerSocket = (SSLServerSocket) sslssf.createServerSocket(port);

		// Store the server's port for the client
		//port = sslServerSocket.getLocalPort();

		// signal the client that the server's ready
		isReady = true;
	}

	@Override
	public SSLSocket getSSLSocket() throws IOException {
		return (SSLSocket) sslServerSocket.accept();
	}

	@Override
	public void cleanup() throws IOException {
		// Do nothing
	}

}
