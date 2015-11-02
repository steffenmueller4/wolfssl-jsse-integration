package edu.kit.aifb.eorg.wolfssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wolfssl.WolfSSLContext;

/**
 * The JSSE API SSLSocketFactory implementation.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public class WolfSSLSocketFactoryImpl extends SSLSocketFactory {

	/**
	 * The SSLContext implementation.
	 */
	private final WolfSSLContext context;
	/**
	 * The logger.
	 */
	private final Logger logger = LoggerFactory.getLogger(WolfSSLSocketFactoryImpl.class);

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The SSLContext implementation.
	 */
	WolfSSLSocketFactoryImpl(WolfSSLContext context) {
		this.context = context;
		logger.debug("WolfSSLSocketFactoryImpl created.");
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return WolfSSLContextImpl.defaultServerSSLParams.getCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return WolfSSLContextImpl.defaultServerSSLParams.getCipherSuites();
	}

	@Override
	public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
		return new WolfSSLSocketImpl(context, true, s);
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
		return new WolfSSLSocketImpl(context, true, host, port);
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
			throws IOException, UnknownHostException {
		return new WolfSSLSocketImpl(context, true, host, port, localHost, localPort);
	}

	@Override
	public Socket createSocket(InetAddress address, int port) throws IOException {
		String host = address.getHostName();
		return new WolfSSLSocketImpl(context, true, host, port);
	}

	@Override
	public Socket createSocket(InetAddress address, int port, InetAddress localHost, int localPort) throws IOException {
		String host = address.getHostName();
		return new WolfSSLSocketImpl(context, true, host, port, localHost, localPort);
	}
}
