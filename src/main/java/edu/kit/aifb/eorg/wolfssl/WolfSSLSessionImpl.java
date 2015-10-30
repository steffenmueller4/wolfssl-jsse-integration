package edu.kit.aifb.eorg.wolfssl;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Hashtable;
import java.util.Set;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The JSSE API SSLSession implementation.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 *
 */
final class WolfSSLSessionImpl extends ExtendedSSLSession {

	/**
	 * The logger.
	 */
	private final Logger logger = LoggerFactory.getLogger(WolfSSLSessionImpl.class);
	private final long creationTime;
	private long lastAccess;
	private WolfSSLSocketImpl referencedSocket;
	private Hashtable<String, Object> values = new Hashtable<>();

	/**
	 * Constructor.
	 * 
	 * @param referencedSocket
	 *            The socket.
	 * @throws IOException
	 *             If an error occurs.
	 */
	WolfSSLSessionImpl(WolfSSLSocketImpl referencedSocket) throws IOException {
		if (referencedSocket == null)
			throw new IOException("referencedSocket cannot be null!");

		this.referencedSocket = referencedSocket;
		this.creationTime = System.currentTimeMillis();
		this.lastAccess = creationTime;
	}

	/**
	 * Updates the last access property.
	 */
	private void updateLastAccess() {
		this.lastAccess = System.currentTimeMillis();
	}

	@Override
	public int getApplicationBufferSize() {
		updateLastAccess();
		return -1;
	}

	@Override
	public String getCipherSuite() {
		updateLastAccess();
		if (referencedSocket == null)
			return null;
		else
			return referencedSocket.session.cipherGetName();
	}

	@Override
	public long getCreationTime() {
		updateLastAccess();
		return creationTime;
	}

	@Override
	public byte[] getId() {
		updateLastAccess();
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			DataOutputStream dos = new DataOutputStream(baos);
			dos.writeLong(referencedSocket.session.getSession());
			dos.close();
			byte[] longBytes = baos.toByteArray();
			return longBytes;
		} catch (IOException | NullPointerException e) {
			return null;
		}
	}

	@Override
	public long getLastAccessedTime() {
		return lastAccess;
	}

	@Override
	public Certificate[] getLocalCertificates() {
		updateLastAccess();
		return null;
	}

	@Override
	public Principal getLocalPrincipal() {
		updateLastAccess();
		return null;
	}

	@Override
	public int getPacketBufferSize() {
		updateLastAccess();
		return -1;
	}

	@Override
	public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
		updateLastAccess();
		return null;
	}

	@Override
	public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
		updateLastAccess();
		return null;
	}

	@Override
	public String getPeerHost() {
		updateLastAccess();

		InetAddress a = referencedSocket.getInetAddress();
		if (a != null)
			return a.getHostName();
		else
			return null;
	}

	@Override
	public int getPeerPort() {
		updateLastAccess();

		return referencedSocket.getPort();
	}

	@Override
	public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
		updateLastAccess();

		return null;
	}

	@Override
	public String getProtocol() {
		updateLastAccess();

		return referencedSocket.session.getVersion();
	}

	@Override
	public SSLSessionContext getSessionContext() {
		updateLastAccess();

		return null;
	}

	@Override
	public Object getValue(String arg0) {
		updateLastAccess();

		return values.get(arg0);
	}

	@Override
	public String[] getValueNames() {
		updateLastAccess();

		Set<String> v = values.keySet();
		return v.toArray(new String[v.size()]);
	}

	@Override
	public void invalidate() {
		logger.warn("Unsupported operation 'invalidate()' invoked!");
	}

	@Override
	public boolean isValid() {
		return true;
	}

	@Override
	public void putValue(String arg0, Object arg1) {
		updateLastAccess();

		values.put(arg0, arg1);
	}

	@Override
	public void removeValue(String arg0) {
		updateLastAccess();

		values.remove(arg0);
	}

	@Override
	public String[] getLocalSupportedSignatureAlgorithms() {
		updateLastAccess();
		return null;
	}

	@Override
	public String[] getPeerSupportedSignatureAlgorithms() {
		updateLastAccess();
		return null;
	}

}