package edu.kit.aifb.eorg.wolfssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wolfssl.WolfSSLContext;

/**
 * The JSSE API SSLServerSocket implementation.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public class WolfSSLServerSocketImpl extends SSLServerSocket {

	/**
	 * The logger.
	 */
	private final Logger logger = LoggerFactory.getLogger(WolfSSLServerSocketImpl.class);
	/**
	 * The wolfSSL context.
	 */
	private final WolfSSLContext context;
	/**
	 * Backlog property.
	 */
	private int backlog = Constants.BACKLOG_DEFAULT;
	/**
	 * SSLParameters.
	 */
	private SSLParameters sslParameters = WolfSSLContextImpl.defaultServerSSLParams;

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The wolfSSL context.
	 * @throws IOException
	 *             If an error occurs.
	 */
	WolfSSLServerSocketImpl(WolfSSLContext context) throws IOException {
		super();

		// Check input
		if (context == null)
			throw new NullPointerException("Context must not be null!");
		this.context = context;

		assert (context != null);
	}

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The wolfSSL context.
	 * @param port
	 *            The port.
	 * @param backlog
	 *            The backlog.
	 * @throws IOException
	 *             If an error occurs.
	 */
	WolfSSLServerSocketImpl(WolfSSLContext context, int port, int backlog) throws IOException {
		this(context, port, backlog, null);
	}

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The wolfSSL context.
	 * @param port
	 *            The port.
	 * @throws IOException
	 *             If an error occurs.
	 */
	WolfSSLServerSocketImpl(WolfSSLContext context, int port) throws IOException {
		this(context, port, Constants.BACKLOG_DEFAULT, null);
	}

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The wolfSSL context.
	 * @param port
	 *            The port.
	 * @param backlog
	 *            The backlog.
	 * @param ifAddress
	 *            The InetAddress.
	 * @throws IOException
	 *             If an error occurs.
	 */
	WolfSSLServerSocketImpl(WolfSSLContext context, int port, int backlog, InetAddress ifAddress) throws IOException {
		this(context);

		// Set the backlog
		this.backlog = backlog;

		if (ifAddress == null)
			ifAddress = InetAddress.getByName(null);
		SocketAddress localSocketAddress = new InetSocketAddress(ifAddress, port);

		bind(localSocketAddress, backlog);
	}

	@Override
	public void bind(SocketAddress endpoint) throws IOException {
		bind(endpoint, backlog);
	}

	@Override
	public void bind(SocketAddress endpoint, int backlog) throws IOException {
		if (endpoint == null)
			throw new NullPointerException();

		InetSocketAddress epoint = (InetSocketAddress) endpoint;

		super.bind(epoint, backlog);
	}

	@Override
	public Socket accept() throws IOException {
		// Create a new socket
		WolfSSLSocketImpl s = new WolfSSLSocketImpl(context, false, sslParameters);
		// use this implementation to accept the socket
		implAccept(s);
		s.doneConnect();
		return s;
	}

	@Override
	public SSLParameters getSSLParameters() {
		assert (sslParameters != null);

		return sslParameters;
	}

	@Override
	public String[] getEnabledCipherSuites() {
		assert (sslParameters != null);

		return sslParameters.getCipherSuites();
	}

	@Override
	public void setEnabledCipherSuites(String[] suites) {
		assert (sslParameters != null);

		sslParameters.setCipherSuites(suites);
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return WolfSSLContextImpl.defaultServerSSLParams.getCipherSuites();
	}

	@Override
	public String[] getSupportedProtocols() {
		return WolfSSLContextImpl.defaultServerSSLParams.getProtocols();
	}

	@Override
	public String[] getEnabledProtocols() {
		assert (sslParameters != null);

		return sslParameters.getProtocols();
	}

	@Override
	public void setEnabledProtocols(String[] protocols) {
		logger.warn("Unsupported operation 'setEnabledProtocols(String[] protocols)' invoked!");
	}

	@Override
	public void setNeedClientAuth(boolean need) {
		logger.warn("Unsupported operation 'setNeedClientAuth(boolean need)' invoked!");
	}

	@Override
	public boolean getNeedClientAuth() {
		return false;
	}

	@Override
	public void setWantClientAuth(boolean want) {
		logger.warn("Unsupported operation 'setWantClientAuth(boolean want)' invoked!");
	}

	@Override
	public boolean getWantClientAuth() {
		return false;
	}

	@Override
	public void setUseClientMode(boolean mode) {
		logger.warn("Unsupported operation 'setUseClientMode(boolean mode)' invoked!");
	}

	@Override
	public boolean getUseClientMode() {
		return false;
	}

	@Override
	public void setEnableSessionCreation(boolean flag) {
		logger.warn("Unsupported operation 'setEnableSessionCreation(boolean flag)' invoked!");
	}

	@Override
	public boolean getEnableSessionCreation() {
		return false;
	}
}
