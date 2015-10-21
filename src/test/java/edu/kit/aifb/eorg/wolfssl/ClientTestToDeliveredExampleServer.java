package edu.kit.aifb.eorg.wolfssl;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClientTestToDeliveredExampleServer extends SSLSocketTestBase {

	private final Logger logger = LoggerFactory.getLogger(SendReceiveByteArrayTest.class);
	private final String msg = "Hello Server, how are you?";
	private final int serverPort = 11111;

	@Test
	public void sendStringToExampleServer() throws NoSuchAlgorithmException {
		client = new SSLSocketTestClient(null, serverPort, true, false) {
			@Override
			public void sendReceive(InputStream inputStream, OutputStream outputStream) throws IOException {
				// Write to the server
				outputStream.write(msg.getBytes());
				outputStream.flush();

				// Receive from the server
				byte[] b = new byte[80];

				int r = inputStream.read(b);
				assertTrue(r > 0);
					
				logger.info("Server answered: {}", new String(b));
			}

			@Override
			public void startup() {
				// Do not wait for someone
			}

			@Override
			public SSLSocket getSSLSocket() throws IOException {
				SSLSocketFactory sslsf = (SSLSocketFactory) sslContext.getSocketFactory();
				return (SSLSocket) sslsf.createSocket("localhost", serverPort);
			}
		};
		client.start();
		assertTrue(client.thrown == null);

		logger.info("Test finished!");
		cleanupAfterTests();
	}
	
	@Override
	public void startClientAndServer() throws NoSuchAlgorithmException, IOException, InterruptedException {
		super.startClientAndServer();
		
		logger.info("Resetting keystore and truststore...");
	}
}
