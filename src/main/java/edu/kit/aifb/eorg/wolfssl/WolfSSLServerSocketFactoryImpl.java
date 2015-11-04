package edu.kit.aifb.eorg.wolfssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

import javax.net.ssl.SSLServerSocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wolfssl.WolfSSLContext;

/**
 * The JSSE API SSLServerSocketFactory implementation.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public class WolfSSLServerSocketFactoryImpl extends SSLServerSocketFactory {

	/**
	 * The SSL context implementation.
	 */
	private final WolfSSLContext context;
	/**
	 * The logger.
	 */
	private final Logger logger = LoggerFactory.getLogger(WolfSSLServerSocketFactoryImpl.class);

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The SSL context.
	 */
	WolfSSLServerSocketFactoryImpl(WolfSSLContext context) {
		this.context = context;
		logger.debug("WolfSSLServerSocketFactoryImpl created.");
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
	public ServerSocket createServerSocket() throws IOException {
		return new WolfSSLServerSocketImpl(context);
	}

	@Override
	public ServerSocket createServerSocket(int port) throws IOException {
		return new WolfSSLServerSocketImpl(context, port);
	}

	@Override
	public ServerSocket createServerSocket(int port, int backlog) throws IOException {
		return new WolfSSLServerSocketImpl(context, port, backlog);
	}

	@Override
	public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
		return new WolfSSLServerSocketImpl(context, port, backlog, ifAddress);
	}
}
