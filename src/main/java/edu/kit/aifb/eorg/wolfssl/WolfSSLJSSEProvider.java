/**
 * Copyright (c) 2013 S. M�ller
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.kit.aifb.eorg.wolfssl;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A custom JSSE Provider for OpenSSL. Please look at the JSSEProvider class of
 * the OpenJDK (http://openjdk.java.net/), too.
 * 
 * @author S. Mueller (AIFB, Karlsruhe Institute of Technology)
 */
public final class WolfSSLJSSEProvider extends Provider {

	/**
	 * {@link java.io.Serializable}
	 */
	private static final long serialVersionUID = 8345922765011851850L;
	/**
	 * The name of the JSSE Provider.
	 */
	private static final String PROVIDER_NAME = "WolfSSLJSSEProvider";
	/**
	 * Info string.
	 */
	private static final String INFO = "wolfSSL JSSE provider (TLSv1.2 only)";
	/**
	 * The version.
	 */
	private static final double VERSION = 1.0;
	/**
	 * The logger.
	 */
	private final Logger logger = LoggerFactory.getLogger(WolfSSLJSSEProvider.class);

	// the FIPS certificate crypto provider that we use to perform all crypto
	// operations. null in non-FIPS mode
	static Provider cryptoProvider;

	/**
	 * Constructor.
	 */
	public WolfSSLJSSEProvider() {
		super(PROVIDER_NAME, VERSION, INFO);
		subclassCheck();

		registerAlgorithms();

		logger.info("WolfSSLJSSEProvider started successfully.");
	}

	/**
	 * Constructor. Use it to enable FIPS mode at runtime.
	 * 
	 * @param cryptoProvider
	 *            The crypto provider.
	 */
	protected WolfSSLJSSEProvider(Provider cryptoProvider) {
		this(checkNull(cryptoProvider), cryptoProvider.getName());
	}

	/**
	 * Constructor. Used to enable FIPS mode from java.security file.
	 * 
	 * @param cryptoProvider
	 *            The crypto provider.
	 */
	protected WolfSSLJSSEProvider(String cryptoProvider) {
		this(null, checkNull(cryptoProvider));
	}

	/**
	 * Checks if the given parameter is null.
	 * 
	 * @param t
	 *            The parameter to check.
	 * @return
	 */
	private static <T> T checkNull(T t) {
		if (t == null) {
			throw new ProviderException("cryptoProvider must not be null");
		}
		return t;
	}

	/**
	 * Constructor.
	 * 
	 * @param cryptoProvider
	 * @param providerName
	 */
	private WolfSSLJSSEProvider(Provider cryptoProvider, String providerName) {
		super(PROVIDER_NAME, VERSION, providerName);
		subclassCheck();
		if (cryptoProvider == null) {
			// Calling Security.getProvider() will cause other providers to be
			// loaded. That is not good but unavoidable here.
			cryptoProvider = Security.getProvider(providerName);
			if (cryptoProvider == null) {
				throw new ProviderException("Crypto provider not installed: " + providerName);
			}
		}
		registerAlgorithms();
	}

	/**
	 * Registers the algorithms.
	 */
	private void registerAlgorithms() {
		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			public Object run() {
				doRegister();
				return null;
			}
		});
	}

	/**
	 * Sub-method to register the algorithms.
	 */
	private void doRegister() {
		// Allow TLSv1.2 only!
		put("Alg.Alias.SSLContext.TLSv1", "TLSv1.2");
		put("Alg.Alias.SSLContext.TLSv1.1", "TLSv1.2");
		put("Alg.Alias.SSLContext.TLS", "TLSv1.2");
		put("Alg.Alias.SSLContext.SSL", "TLSv1.2");
		put("Alg.Alias.SSLContext.SSLv3", "TLSv1.2");
		put("SSLContext.TLSv1.2", "edu.kit.aifb.eorg.wolfssl.WolfSSLContextImpl");
		put("SSLContext.Default", "edu.kit.aifb.eorg.wolfssl.WolfSSLContextImpl");

		logger.info("Experimental wolfSSL support activated.");
	}

	private void subclassCheck() {
		if (getClass() != edu.kit.aifb.eorg.wolfssl.WolfSSLJSSEProvider.class) {
			throw new AssertionError("Illegal subclass: " + getClass());
		}
	}
}
