package edu.kit.aifb.eorg.wolfssl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLSession;

/**
 * The JSSE API SSLSocket implementation.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public class WolfSSLSocketImpl extends BaseSSLSocketImpl {

	/**
	 * The logger.
	 */
	private final Logger logger = LoggerFactory.getLogger(WolfSSLSocketImpl.class);
	/**
	 * The JSSE context implementation.
	 */
	private final WolfSSLContext context;
	/**
	 * The application output stream.
	 */
	private WolfSSLAppOutputStream appOutputStream;
	/**
	 * The application input stream.
	 */
	private WolfSSLAppInputStream appInputStream;
	/**
	 * The wolfSSL session.
	 */
	WolfSSLSession session;
	/**
	 * Indicates whether this is a client/server socket.
	 */
	private boolean clientMode;
	/**
	 * The JSSE session implementation.
	 */
	private WolfSSLSessionImpl jsseSession;
	/**
	 * The sslParameters.
	 */
	private SSLParameters sslParameters = WolfSSLContextImpl.defaultServerSSLParams;

	/**
	 * Constructor.
	 * 
	 * @param context
	 *            The JSSE context implementation.
	 * @param clientMode
	 *            Indicates whether this is a client/server socket.
	 * @param host
	 *            The hostname.
	 * @param port
	 *            The port.
	 * @throws IOException
	 *             If an error occurs.
	 */
	WolfSSLSocketImpl(WolfSSLContext context, boolean clientMode, String host, int port) throws IOException {
		super();
		this.context = context;
		this.clientMode = clientMode;
		this.jsseSession = new WolfSSLSessionImpl(this);

		assert (context != null);
		assert (jsseSession != null);

		SocketAddress socketAddress = host != null ? new InetSocketAddress(host, port)
				: new InetSocketAddress(InetAddress.getByName(null), port);

		// Connect the socket
		connect(socketAddress, 0);
	}

	/**
	 * Constructor used by serverSocket.accept().
	 * 
	 * @param context
	 *            The {@link WolfSSLContextImpl}.
	 * @param clientMode
	 * @param socket_t
	 * @throws IOException
	 */
	WolfSSLSocketImpl(WolfSSLContext context, boolean clientMode, SSLParameters sslParameters) throws IOException {
		super();
		this.context = context;
		this.clientMode = clientMode;
		this.jsseSession = new WolfSSLSessionImpl(this);
		this.sslParameters = sslParameters;

		assert (context != null);
		assert (jsseSession != null);
	}

	/**
	 * Constructor invoked with a connected underlying socket.
	 * 
	 * @param context
	 * @param clientMode
	 * @param s
	 * @throws IOException
	 */
	public WolfSSLSocketImpl(WolfSSLContext context, boolean clientMode, Socket s) throws IOException {
		super(s);
		if (!s.isConnected()) {
			throw new SocketException("Underlying socket is not connected");
		}
		this.context = context;
		this.clientMode = clientMode;
		this.jsseSession = new WolfSSLSessionImpl(this);

		assert (context != null);
		assert (jsseSession != null);

		// Invoke doneConnect to get an SSL socket
		doneConnect();
	}

	/**
	 * 
	 * @param context
	 * @param clientMode
	 * @param host
	 * @param port
	 * @param localHost
	 * @param localPort
	 * @throws IOException
	 */
	public WolfSSLSocketImpl(WolfSSLContext context, boolean clientMode, String host, int port, InetAddress localHost,
			int localPort) throws IOException {
		this(context, clientMode, WolfSSLContextImpl.defaultServerSSLParams);

		bind(new InetSocketAddress(localHost, localPort));

		SocketAddress socketAddress = host != null ? new InetSocketAddress(host, port)
				: new InetSocketAddress(InetAddress.getByName(null), port);

		// Connect the socket
		connect(socketAddress, 0);
	}

	/**
	 * Encapsulates things that have to be done after the socket has been
	 * connected.
	 * 
	 * @throws IOException
	 *             If an error occurs.
	 */
	void doneConnect() throws IOException {
		appOutputStream = new WolfSSLAppOutputStream(this);
		appInputStream = new WolfSSLAppInputStream(this);

		assert (appOutputStream != null);
		assert (appInputStream != null);
		assert (context != null);
		assert (jsseSession != null);
		assert (sslParameters != null);

		// Get the enabled cipher suites
		String list = WolfSSLCipherSuiteList.getWolfSSLCipherSuiteList(sslParameters.getCipherSuites());
		logger.debug("List of enabled cipher suites: {}", list);

		try {
			// Create a new session
			session = new WolfSSLSession(context);
		} catch (WolfSSLException e) {
			throw new IOException("Cannot create session: " + e.getMessage());
		}

		logger.debug("Session created.");

		assert (session != null);
		assert (list != null && !list.isEmpty());

		int ret = session.setCipherList(list);
		if (ret != WolfSSL.SSL_SUCCESS) {
			logger.error("setCipherList({}) not successful!", list);
		} else {
			logger.debug("setCipherList({}) successful.", list);
		}

		// TODO: Fix it for production!
		ret = session.disableCRL();
		if (ret != WolfSSL.SSL_SUCCESS) {
			throw new IOException("failed to disable CRL check");
		}

		// Set the file descriptor
		ret = session.setFd(this);
		if (ret != WolfSSL.SSL_SUCCESS) {
			throw new IOException("Failed to set file descriptor");
		}
		logger.debug("setFd successful.");

		if (clientMode) {
			ret = session.connect();
		} else {
			ret = session.accept();
		}
		if (ret != WolfSSL.SSL_SUCCESS) {
			int err = session.getError(ret);
			String errString = WolfSSL.getErrorString(err);
			throw new IOException("wolfSSL_connect failed. err = " + err + ", " + errString);
		}

		if (clientMode)
			logger.debug("client doneConnect() successful.");
		else
			logger.debug("server doneConnect() successful.");
	}

	/**
	 * Writes to the SSLSocket.
	 * 
	 * @param buffer
	 *            The bytes that should be written.
	 * @param length
	 *            The length.
	 */
	void write(byte[] buffer, int length) {
		int sendBytes = session.write(buffer, length);

		logger.debug("Written {} bytes of {}.", sendBytes, length);
	}

	/**
	 * Reads from the SSLSocket.
	 * 
	 * @param buffer
	 *            The buffer into that the bytes should be written.
	 * @param length
	 *            The length.
	 * @return The number of bytes read upon success.
	 */
	int read(byte[] buffer, int length) {
		int read = session.read(buffer, length);

		logger.debug("Read {} bytes.", read);

		return read;
	}

	@Override
	public void connect(SocketAddress endpoint, int timeout) throws IOException {
		if (endpoint == null)
			throw new NullPointerException();

		// Connect the socket
		super.connect(endpoint, timeout);

		// Invoke doneConnect to get an SSL socket
		doneConnect();
	}

	@Override
	public void close() throws IOException {
		assert (session != null);

		session.shutdownSSL();
		session.freeSSL();
		super.close();
	}

	@Override
	public OutputStream getOutputStream() throws IOException {
		assert (appOutputStream != null);

		return appOutputStream;
	}

	@Override
	public InputStream getInputStream() throws IOException {
		assert (appInputStream != null);

		return appInputStream;
	}

	@Override
	public String[] getSupportedCipherSuites() {
		assert (WolfSSLContextImpl.defaultServerSSLParams != null);

		return WolfSSLContextImpl.defaultServerSSLParams.getCipherSuites();
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
	public String[] getSupportedProtocols() {
		return WolfSSLContextImpl.defaultServerSSLParams.getProtocols();
	}

	@Override
	public String[] getEnabledProtocols() {
		assert (session != null);

		List<String> enabled = new ArrayList<String>();
		enabled.add(session.getVersion());

		return enabled.toArray(new String[enabled.size()]);
	}

	@Override
	public void setEnabledProtocols(String[] protocols) {
		logger.warn("Unsupported operation 'setEnabledProtocols(String[] protocols)' invoked!");
	}

	@Override
	public SSLSession getSession() {
		assert (jsseSession != null);

		return jsseSession;
	}

	@Override
	public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
		logger.warn(
				"Unsupported operation 'addHandshakeCompletedListener(HandshakeCompletedListener listener)' invoked!");
	}

	@Override
	public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
		logger.warn(
				"Unsupported operation 'removeHandshakeCompletedListener(HandshakeCompletedListener listener)' invoked!");
	}

	@Override
	public void startHandshake() throws IOException {
		logger.warn("Unsupported operation 'startHandshake()' invoked!");
	}

	@Override
	public void setUseClientMode(boolean mode) {
		this.clientMode = mode;
	}

	@Override
	public boolean getUseClientMode() {
		return this.clientMode;
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
	public void setEnableSessionCreation(boolean flag) {
		logger.warn("Unsupported operation 'setEnableSessionCreation(boolean flag)' invoked!");
	}

	@Override
	public boolean getEnableSessionCreation() {
		return false;
	}

	@Override
	public SSLParameters getSSLParameters() {
		assert (sslParameters != null);

		return sslParameters;
	}
}
