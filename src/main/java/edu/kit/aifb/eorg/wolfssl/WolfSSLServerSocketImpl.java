package edu.kit.aifb.eorg.wolfssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

import javax.net.ssl.SSLServerSocket;

import com.wolfssl.WolfSSLContext;

/**
 * The JSSE API SSLServerSocket implementation.
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
public class WolfSSLServerSocketImpl extends SSLServerSocket {

	/**
	 * The default value for backlog.
	 */
	private static final int BACKLOG_DEFAULT = 50;
	private final WolfSSLContext context;
	private int backlog = BACKLOG_DEFAULT;
	

	WolfSSLServerSocketImpl(WolfSSLContext context) throws IOException{
		super();
		
		// Check input
		if(context == null)
			throw new NullPointerException("Context must not be null!");
		this.context = context;
		
		assert (context != null);
	}
			
	WolfSSLServerSocketImpl(WolfSSLContext context, int port, int backlog) throws IOException {
		this(context, port, backlog, null);
	}
	
	WolfSSLServerSocketImpl(WolfSSLContext context, int port) throws IOException {
		this(context, port, BACKLOG_DEFAULT, null);
	}
	
	WolfSSLServerSocketImpl(WolfSSLContext context, int port, int backlog, InetAddress ifAddress) throws IOException {
		this(context);
		
		// Set the backlog
		this.backlog = backlog;
		
		if(ifAddress == null)
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
		WolfSSLSocketImpl s = new WolfSSLSocketImpl(context, false);
		// use this implementation to accept the socket
		implAccept(s);
		s.doneConnect();
		return s;
	}

	@Override
	public String[] getEnabledCipherSuites() {
		assert(WolfSSLContextImpl.defaultServerSSLParams != null);
		
		return WolfSSLContextImpl.defaultServerSSLParams.getCipherSuites();
	}

	@Override
	public void setEnabledCipherSuites(String[] suites) {
		// TODO
	}

	@Override
	public String[] getSupportedCipherSuites() {
		assert(WolfSSLContextImpl.defaultServerSSLParams != null);
		
		return WolfSSLContextImpl.defaultServerSSLParams.getCipherSuites();
	}

	@Override
	public String[] getSupportedProtocols() {
		assert(WolfSSLContextImpl.defaultServerSSLParams != null);
		
		return WolfSSLContextImpl.defaultServerSSLParams.getProtocols();
	}

	@Override
	public String[] getEnabledProtocols() {
		assert(WolfSSLContextImpl.defaultServerSSLParams != null);
		
		return WolfSSLContextImpl.defaultServerSSLParams.getProtocols();
	}

	@Override
	public void setEnabledProtocols(String[] protocols) {

	}

	@Override
	public void setNeedClientAuth(boolean need) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean getNeedClientAuth() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setWantClientAuth(boolean want) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean getWantClientAuth() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setUseClientMode(boolean mode) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean getUseClientMode() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setEnableSessionCreation(boolean flag) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean getEnableSessionCreation() {
		return true;
	}
}
