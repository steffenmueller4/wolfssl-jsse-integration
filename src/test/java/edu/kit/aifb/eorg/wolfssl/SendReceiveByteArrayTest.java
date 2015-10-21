package edu.kit.aifb.eorg.wolfssl;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tests the AtlasSSLSocketImpl sending and receiving 100 times a specific byte array.
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public class SendReceiveByteArrayTest extends SSLSocketTestBase {
	
	private final Logger logger = LoggerFactory.getLogger(SendReceiveByteArrayTest.class);
	
	@Test
	public void sendReceiveByteArrayTest() throws NoSuchAlgorithmException,
			IOException, InterruptedException {
		final int COUNT = 100;
		// Initialize the byte array
		final byte[] SEND_RECEIVE = new byte[] { 80, 21, 38, 123, 98, 41, 89,
				75, 65, 90, 86, 71, 29, 34, 56, 75, 66, 79, 1, 0, 90, 14, 56,
				57, 61, 34, 78, 91, 1, 2, 3 };
		server = new SSLSocketTestServer(11111, true, false) {
			@Override
			public void sendReceive(InputStream inputStream, OutputStream outputStream) throws IOException {
				for (int i = 0; i < COUNT; i++) {
					// Read the byte array
					byte[] buffer = new byte[SEND_RECEIVE.length];
					int b = inputStream.read(buffer);

					assertTrue(b == SEND_RECEIVE.length);
					assertTrue(Arrays.equals(buffer, SEND_RECEIVE));

					// Send the byte array
					outputStream.write(SEND_RECEIVE);
					outputStream.flush();
				}
			}
		};
		server.start();
		client = new SSLSocketTestClient(server, 11111, true, false) {
			@Override
			public void sendReceive(InputStream inputStream, OutputStream outputStream) throws IOException {
				for (int i = 0; i < COUNT; i++) {
					// Send the byte array
					outputStream.write(SEND_RECEIVE);
					outputStream.flush();

					// Receive the byte array
					byte[] buffer = new byte[SEND_RECEIVE.length];
					int b = inputStream.read(buffer);

					assertTrue(b == SEND_RECEIVE.length);

					assertTrue(Arrays.equals(buffer, SEND_RECEIVE));
				}
			}
		};
		client.start();

		server.join();
		logger.info("Server joined");

		assertTrue(server.thrown == null);
		assertTrue(client.thrown == null);

		logger.info("Test finished!");
		cleanupAfterTests();
	}
	
}

