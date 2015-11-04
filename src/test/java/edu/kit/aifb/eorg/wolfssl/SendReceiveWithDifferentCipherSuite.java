package edu.kit.aifb.eorg.wolfssl;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tests the AtlasSSLSocketImpl sending and receiving 100 times a specific byte
 * array.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public class SendReceiveWithDifferentCipherSuite extends SSLSocketTestBase {

	private final Logger logger = LoggerFactory.getLogger(SendReceiveWithDifferentCipherSuite.class);
	private final int serverPort = 11111;
	private final String sendMsg = "I am a message to send.";
	private final String receiveMsg = "I am a message to receive.";
	private static final String[] CIPHER_SUITES = new String[] { "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" };

	@Test
	public void sendReceiveWithDifferentCipherSuites()
			throws NoSuchAlgorithmException, IOException, InterruptedException {
		// Initialize the byte array
		server = new SSLSocketTestServer(serverPort, true, false) {
			@Override
			public void startup() throws IOException {
				SSLServerSocketFactory sslssf = (SSLServerSocketFactory) sslContext.getServerSocketFactory();
				sslServerSocket = (SSLServerSocket) sslssf.createServerSocket(port);

				logger.info("Setting Cipher Suite");
				sslServerSocket.setEnabledCipherSuites(CIPHER_SUITES);

				// signal the client that the server's ready
				isReady = true;
			}

			@Override
			public void sendReceive(InputStream inputStream, OutputStream outputStream) throws IOException {
				// Read the byte array
				byte[] buffer = new byte[receiveMsg.getBytes().length];
				int b = inputStream.read(buffer);

				assertTrue(b == receiveMsg.getBytes().length);
				assertTrue(Arrays.equals(buffer, receiveMsg.getBytes()));

				// Send the byte array
				outputStream.write(sendMsg.getBytes());
				outputStream.flush();
			}
		};
		server.start();
		client = new SSLSocketTestClient(server, serverPort, true, false) {
			@Override
			public void sendReceive(InputStream inputStream, OutputStream outputStream) throws IOException {
				// Send the byte array
				outputStream.write(receiveMsg.getBytes());
				outputStream.flush();

				// Receive the byte array
				byte[] buffer = new byte[sendMsg.getBytes().length];
				int b = inputStream.read(buffer);

				assertTrue(b == sendMsg.getBytes().length);

				assertTrue(Arrays.equals(buffer, sendMsg.getBytes()));
			}

			@Override
			public SSLSocket getSSLSocket() throws IOException {
				SSLSocketFactory sslsf = (SSLSocketFactory) sslContext.getSocketFactory();
				SSLSocket s = (SSLSocket) sslsf.createSocket("localhost", server.port);
				s.setEnabledCipherSuites(CIPHER_SUITES);
				return s;
			}
		};
		client.start();

		String negClientCipherSuite = client.sslSocket.getSession().getCipherSuite();
		String negServerCipherSuite = server.sslSocket.getSession().getCipherSuite();

		assertTrue(negClientCipherSuite != null && !negClientCipherSuite.isEmpty());
		assertTrue(negServerCipherSuite != null && !negServerCipherSuite.isEmpty());

		logger.info("Negotiated cipher suite is : " + negClientCipherSuite);

		assertTrue(Arrays.equals(CIPHER_SUITES, new String[] { negClientCipherSuite }));
		assertTrue(Arrays.equals(CIPHER_SUITES, new String[] { negServerCipherSuite }));

		server.join();
		logger.info("Server joined");

		assertTrue(server.thrown == null);
		assertTrue(client.thrown == null);

		logger.info("Test finished!");
		cleanupAfterTests();
	}

}
