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
 * Tests the AtlasSSLSocketImpl sending and receiving 100 times a specific byte
 * array.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public class SendReceiveByteArrayTest2 extends SSLSocketTestBase {

	private final Logger logger = LoggerFactory.getLogger(SendReceiveByteArrayTest2.class);
	private final int serverPort = 11111;
	private final String sendMsg = "I am a message to send.";
	private final String receiveMsg = "I am a message to receive.";

	@Test
	public void sendReceiveByteArrayTest() throws NoSuchAlgorithmException, IOException, InterruptedException {
		// Initialize the byte array
		server = new SSLSocketTestServer(serverPort, true, false) {
			@Override
			public void sendReceive(InputStream inputStream, OutputStream outputStream) throws IOException {
				for (int i = 0; i < 100; i++) {
					// Read the byte array
					byte[] buffer = new byte[receiveMsg.getBytes().length];
					int b = inputStream.read(buffer, 0, receiveMsg.getBytes().length);

					assertTrue(b == receiveMsg.getBytes().length);
					assertTrue(Arrays.equals(buffer, receiveMsg.getBytes()));

					// Send the byte array
					outputStream.write(sendMsg.getBytes());
					outputStream.flush();
				}
			}
		};
		server.start();
		client = new SSLSocketTestClient(server, serverPort, true, false) {
			@Override
			public void sendReceive(InputStream inputStream, OutputStream outputStream) throws IOException {
				for (int i = 0; i < 100; i++) {
					// Send the byte array
					outputStream.write(receiveMsg.getBytes(), 0, receiveMsg.getBytes().length);
					outputStream.flush();

					// Receive the byte array
					byte[] buffer = new byte[sendMsg.getBytes().length];
					int b = inputStream.read(buffer);

					assertTrue(b == sendMsg.getBytes().length);

					assertTrue(Arrays.equals(buffer, sendMsg.getBytes()));
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
