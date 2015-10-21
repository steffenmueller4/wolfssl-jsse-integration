package edu.kit.aifb.eorg.wolfssl;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides a basic client for the tests.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
abstract class SSLSocketTestClient extends SSLSocketBaseClientServer {
	
	private final SSLSocketTestServer server;
	private final Logger logger = LoggerFactory.getLogger(SSLSocketTestClient.class);

	public SSLSocketTestClient(SSLSocketTestServer server, int port,
			boolean stopOnException, boolean registerHandshakeCompletedListener)
			throws NoSuchAlgorithmException {
		super("Client", port, stopOnException, registerHandshakeCompletedListener);

		this.server = server;
	}

	public SSLSocketTestClient(SSLSocketTestServer server, int port,
			boolean registerHandshakeCompletedListener)
			throws NoSuchAlgorithmException {
		super("Client", port, false, registerHandshakeCompletedListener);

		this.server = server;
	}

	public void start() {
		run();
	}

	@Override
	public void startup() {
		try {
			/*
			 * Wait for server to get started.
			 */
			while (!server.isReady) {
				Thread.sleep(50);
			}
		} catch (InterruptedException e) {
			thrown = e;
			logger.error("Exception in Client!", e);
		}
	}

	@Override
	public void cleanup() throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public SSLSocket getSSLSocket() throws IOException {
		SSLSocketFactory sslsf = (SSLSocketFactory) sslContext
				.getSocketFactory();
		return (SSLSocket) sslsf.createSocket("localhost", server.port);
	}
}
