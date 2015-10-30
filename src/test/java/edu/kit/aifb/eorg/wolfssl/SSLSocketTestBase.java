package edu.kit.aifb.eorg.wolfssl;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.junit.After;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public abstract class SSLSocketTestBase {

	protected static final boolean DEBUG = false;

	protected SSLSocketTestServer server;
	protected SSLSocketTestClient client;
	private final Logger logger = LoggerFactory
			.getLogger(SSLSocketTestBase.class);

	/**
	 * Starts the client and the server.
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InterruptedException
	 */
	@Before
	public void startClientAndServer() throws NoSuchAlgorithmException,
			IOException, InterruptedException {
		Security.insertProviderAt(
				new edu.kit.aifb.eorg.wolfssl.WolfSSLJSSEProvider(), 1);

		// reject client initialized SSL renegotiation.
		System.setProperty("jdk.tls.rejectClientInitiatedRenegotiation",
				"false");
		
		System.setProperty("edu.kit.aifb.eorg.atlas.ssl.allowExperimentalSockets", "true");
		
		if (DEBUG)
			System.setProperty("javax.net.debug", "all");
		
		logger.info("Test initialized successfully.");
	}

	/**
	 * Cleans up the test.
	 */
	protected void cleanupAfterTests() {
		server = null;
		client = null;
	}

	@After
	public void closeClientAndServer() throws IOException {		
		logger.info("Test closed successfully.");
	}
}

