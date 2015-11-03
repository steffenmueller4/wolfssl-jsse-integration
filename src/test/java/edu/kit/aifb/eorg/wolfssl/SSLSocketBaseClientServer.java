package edu.kit.aifb.eorg.wolfssl;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A test server skeleton.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
abstract class SSLSocketBaseClientServer extends Thread implements HandshakeCompletedListener {

	/**
	 * Indicates if this instance is ready, e.g., if the server is ready to
	 * accept incomming connections.
	 */
	public volatile boolean isReady = false;
	/**
	 * The port of the SSLSocket.
	 */
	public volatile int port;
	/**
	 * Exceptions thrown during the run.
	 */
	public volatile Exception thrown;
	/**
	 * The number of completed handshakes.
	 */
	public volatile int handshakesCompleted = 0;
	/**
	 * The handshake lock.
	 */
	private final Object handshakeListenerLock = new Object();
	/**
	 * The SSLContext.
	 */
	SSLContext sslContext;
	/**
	 * The handshake listener.
	 */
	protected HandshakeCompletedListener handshakeListener;
	/**
	 * The logger.
	 */
	private final Logger logger = LoggerFactory.getLogger(SSLSocketBaseClientServer.class);
	/**
	 * Indicates if the test should stop on an exception.
	 */
	protected final boolean stopOnException;
	/**
	 * Indicates if a {@link HandshakeCompletedListener} should be registered.
	 */
	protected final boolean registerHandshakeCompletedListener;
	/**
	 * The {@link SSLSocket}.
	 */
	SSLSocket sslSocket;

	/**
	 * Constructor.
	 * 
	 * @param name
	 *            The name of the Thread
	 * @param stopOnException
	 *            Indicates if the test should stop on an exception.
	 * @param registerHandshakeCompletedListener
	 *            Indicates if a {@link HandshakeCompletedListener} should be
	 *            registered.
	 * @throws NoSuchAlgorithmException
	 *             If the {@link SSLContext} could not be instantiated.
	 */
	public SSLSocketBaseClientServer(String name, int port, boolean stopOnException,
			boolean registerHandshakeCompletedListener) throws NoSuchAlgorithmException {
		this.setName(name);

		this.sslContext = SSLContext.getDefault();
		this.port = port;
		this.stopOnException = stopOnException;
		this.registerHandshakeCompletedListener = registerHandshakeCompletedListener;
	}

	@Override
	public void run() {
		try {
			startup();

			// Accept the socket connection
			sslSocket = getSSLSocket();
			assertNotNull(sslSocket);
			assertTrue(sslSocket.isConnected());
			try {
				if (registerHandshakeCompletedListener)
					sslSocket.addHandshakeCompletedListener(this);

				// Get the streams
				InputStream inputStream = sslSocket.getInputStream();
				OutputStream outputStream = sslSocket.getOutputStream();

				assertNotNull(inputStream);
				assertNotNull(outputStream);

				// Invoke the test case implementation
				sendReceive(inputStream, outputStream);
			} finally {
				sslSocket.close();
			}

			cleanup();
		} catch (Exception e) {
			thrown = e;
			logger.error("Error in server", e);
			if (stopOnException) {
				return;
			}
		}
	}

	/**
	 * Starts the neccessary things to accept incomming connection (server) /
	 * start connections (client).
	 * 
	 * @return
	 * @throws IOException
	 */
	public abstract void startup() throws IOException;

	/**
	 * Cleans up the neccessary things.
	 * 
	 * @throws IOException
	 *             If an IOException occurs
	 */
	public abstract void cleanup() throws IOException;

	/**
	 * Gets the {@link SSLSocket}, i.e., retuns the {@link SSLSocket} after
	 * accept (Server) / connect (Client).
	 * 
	 * @return
	 * @throws IOException
	 */
	public abstract SSLSocket getSSLSocket() throws IOException;

	/**
	 * Here we go for the test case implementation.
	 * 
	 * @throws IOException
	 *             If something goes wrong.
	 */
	public abstract void sendReceive(InputStream inputStream, OutputStream outputStream) throws IOException;

	@Override
	public void handshakeCompleted(HandshakeCompletedEvent event) {
		synchronized (handshakeListenerLock) {
			handshakesCompleted++;
		}
	}
}