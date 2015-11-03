package edu.kit.aifb.eorg.wolfssl;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestSetCipherSuites extends SSLSocketTestBase {

	private final Logger logger = LoggerFactory.getLogger(SendReceiveByteArrayTest.class);
	private final String clientMsg = "Hello Server, how are you?";
	private final String serverMsg = "Hello Client, I am fine.";
	private final int serverPort = 11111;
	private final String CIPHER_SUITE = "TLS_RSA_WITH_HC_128_MD5";

	@Test
	public void testSetCipherSuites() throws NoSuchAlgorithmException, InterruptedException {
		
		server = new SSLSocketTestServer(serverPort, true, false) {
			@Override
			public void sendReceive(InputStream inputStream, OutputStream outputStream) throws IOException {
				// Receive from the server
				byte[] b = new byte[clientMsg.getBytes().length];

				int r = inputStream.read(b);
				assertTrue(r > 0);
				assertTrue(Arrays.equals(b, clientMsg.getBytes()));
				
				// Write to the server
				outputStream.write(serverMsg.getBytes());
				outputStream.flush();
			}
			
			@Override
			public void startup() throws IOException {
				SSLServerSocketFactory sslssf = (SSLServerSocketFactory) sslContext
						.getServerSocketFactory();
				sslServerSocket = (SSLServerSocket) sslssf.createServerSocket(port);

				// Store the server's port for the client
				sslServerSocket.setEnabledCipherSuites(new String[]{CIPHER_SUITE});

				// signal the client that the server's ready
				isReady = true;
			}
		};
		server.start();
		client = new SSLSocketTestClient(server, serverPort, true, false) {
			@Override
			public void sendReceive(InputStream inputStream, OutputStream outputStream) throws IOException {
				// Write to the server
				outputStream.write(clientMsg.getBytes());
				outputStream.flush();

				// Receive from the server
				byte[] b = new byte[serverMsg.getBytes().length];

				int r = inputStream.read(b);
				assertTrue(r > 0);
				assertTrue(Arrays.equals(b, serverMsg.getBytes()));
			}
		};
		client.start();
		
		String serverSuite = server.sslSocket.getSession().getCipherSuite();
		String clientSuite = client.sslSocket.getSession().getCipherSuite();
		
		assertTrue(serverSuite != null && !serverSuite.isEmpty());
		assertTrue(clientSuite != null && !clientSuite.isEmpty());
		assertTrue(serverSuite.equals(CIPHER_SUITE));
		assertTrue(clientSuite.equals(CIPHER_SUITE));

		server.join();
		logger.info("Server joined");

		assertTrue(server.thrown == null);
		assertTrue(client.thrown == null);

		logger.info("Test finished!");
		cleanupAfterTests();
	}
}
