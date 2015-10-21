package edu.kit.aifb.eorg.wolfssl;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServerTestFromDeliveredExampleClient extends SSLSocketTestBase {
	private final Logger logger = LoggerFactory.getLogger(SendReceiveByteArrayTest.class);
	private final String msg = "I hear you fa shizzle, from Java!";
	private final int serverPort = 11111;
	
	@Test
	public void receiveStringFromExampleClient() throws NoSuchAlgorithmException, InterruptedException{
		server = new SSLSocketTestServer(serverPort, true, false) {
			
			@Override
			public void sendReceive(InputStream inputStream, OutputStream outputStream) throws IOException {
				byte[] b = new byte[80];
				int r = inputStream.read(b);
				
				assertTrue(r > 0);
				
				logger.info("Client told me: {}", new String(b));
				
				outputStream.write(msg.getBytes());
				outputStream.flush();
			}
			
			@Override
			public void startup() throws IOException {
				SSLServerSocketFactory sslssf = (SSLServerSocketFactory) sslContext
						.getServerSocketFactory();
				sslServerSocket = (SSLServerSocket) sslssf.createServerSocket(serverPort);

				// Store the server's port for the client
				port = sslServerSocket.getLocalPort();

				// signal the client that the server's ready
				isReady = true;
			}
		};
		
		server.start();
		
		server.join();
		assertTrue(server.thrown == null);

		logger.info("Test finished!");
		cleanupAfterTests();
	}
	
	@Override
	public void startClientAndServer() throws NoSuchAlgorithmException, IOException, InterruptedException {
		super.startClientAndServer();
		
		logger.info("Resetting keystore and truststore...");

		System.setProperty("javax.net.ssl.keyStore", "/home/steffen-adm/workspace_wolfssl/wolfssl-jni-1.2.0/examples/certs/server-key.pem");
		System.setProperty("javax.net.ssl.trustStore", "/home/steffen-adm/workspace_wolfssl/wolfssl-jni-1.2.0/examples/certs/server-cert.pem");
	}
}
