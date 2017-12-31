#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
package ${package};

import java.awt.Desktop;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http2.HTTP2Cipher;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.websocket.server.WebSocketHandler;
import org.eclipse.jetty.websocket.servlet.WebSocketServletFactory;

/**
 * Hello world!
 *
 */
public class App {

	public static final Logger LOG = LogManager.getLogger(App.class);

	private static final String STORE_PASS = "password";

	private static final int SERVER_PORT = 8080;

	public static Certificate initCert(final Provider provider, final KeyPair keyPair, final String subjectDN)
			throws OperatorCreationException, CertificateException, IOException {

		final X500Name dnName = new X500Name(subjectDN);
		// Using the current timestamp as the certificate serial number
		final BigInteger certSerialNumber = new BigInteger(Long.toString(System.currentTimeMillis()));
		final ZonedDateTime zoned = LocalDate.now().atStartOfDay(ZoneId.systemDefault());
		final Date start = Date.from(zoned.toInstant());
		final Date end = Date.from(zoned.plusYears(1).toInstant());

		// Use appropriate signature algorithm based on your keyPair algorithm.
		final String signatureAlgorithm = "SHA256WithRSA";
		final ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

		final JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, start,
				end, dnName, keyPair.getPublic());

		// Extensions --------------------------
		// Basic Constraints
		// true for CA, false for EndEntity
		final BasicConstraints basicConstraints = new BasicConstraints(true);

		// Basic Constraints is usually marked as critical.
		certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

		// -------------------------------------
		return new JcaX509CertificateConverter().setProvider(provider).getCertificate(certBuilder.build(contentSigner));
	}

	private static HttpConfiguration initConfig() {
		final HttpConfiguration config = new HttpConfiguration();
		// Hide server name
		config.setSendServerVersion(false);
		// HSTS 15768000 seconds, 6 months
		final SecureRequestCustomizer custom = new SecureRequestCustomizer(true, 15768000, false);
		config.addCustomizer(custom);
		// Set secure port
		config.setSecurePort(SERVER_PORT);
		return config;
	}

	private static ContextHandlerCollection initHandlers() {
		final ContextHandler ws = initWebSocketHandler("/events", MyWebSocket.class);
		final ContextHandler root = new ContextHandler();
		root.setContextPath("/");
		final ResourceHandler res = new ResourceHandler();
		res.setWelcomeFiles(new String[]{"index.html"});
		final URL url = App.class.getResource("");
		res.setBaseResource(Resource.newResource(url));
		root.setHandler(res);
		final ContextHandlerCollection handlers = new ContextHandlerCollection(ws, root);
		return handlers;
	}

	private static KeyStore initKeyStore(final String password)
			throws GeneralSecurityException, OperatorCreationException, IOException {

		final Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);
		final KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(null, password.toCharArray());
		// generate a key pair
		final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
		keyGen.initialize(4096, new SecureRandom());
		final KeyPair keyPair = keyGen.generateKeyPair();

		final Certificate cert = initCert(bcProvider, keyPair, "CN=CA");
		final Certificate[] chain = new Certificate[]{cert};
		keystore.setKeyEntry("localhost", keyPair.getPrivate(), password.toCharArray(), chain);

		return keystore;
	}

	private static Server initServer(final HttpConfiguration config, final SslContextFactory factory) {
		final Server server = new Server();
		final HttpConnectionFactory http1 = new HttpConnectionFactory(config);
		final SslConnectionFactory ssl = new SslConnectionFactory(factory, HttpVersion.HTTP_1_1.asString());
		final ServerConnector connector = new ServerConnector(server, ssl, http1);
		connector.setPort(SERVER_PORT);
		server.setConnectors(new Connector[]{connector});
		return server;
	}

	private static Server initServer2(final HttpConfiguration config, final SslContextFactory factory) {
		final Server server = new Server();
		final HttpConnectionFactory http1 = new HttpConnectionFactory(config);
		final HTTP2ServerConnectionFactory http2 = new HTTP2ServerConnectionFactory(config);
		final ALPNServerConnectionFactory alpn = new ALPNServerConnectionFactory();
		// sets default protocol final to HTTP 1.1
		alpn.setDefaultProtocol(http1.getProtocol());

		final SslConnectionFactory ssl = new SslConnectionFactory(factory, alpn.getProtocol());
		final ServerConnector connector = new ServerConnector(server, ssl, alpn, http2, http1);
		connector.setPort(SERVER_PORT);
		server.setConnectors(new Connector[]{connector});
		return server;
	}

	private static SslContextFactory initSSLFactory()
			throws GeneralSecurityException, OperatorCreationException, IOException {
		final SslContextFactory factory = new SslContextFactory();
		factory.setKeyStore(initKeyStore(STORE_PASS));
		factory.setKeyStorePassword(STORE_PASS);
		factory.setCipherComparator(HTTP2Cipher.COMPARATOR);
		factory.setIncludeProtocols("TLSv1.2");
		factory.setIncludeCipherSuites("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
				"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
		factory.setUseCipherSuitesOrder(true);
		factory.setEnableOCSP(true);
		return factory;
	}

	private static ContextHandler initWebSocketHandler(final String path, final Class<?> webSocketClass) {
		final ContextHandler ws = new ContextHandler();
		ws.setContextPath(path);
		ws.setHandler(new WebSocketHandler() {
			@Override
			public void configure(final WebSocketServletFactory factory) {
				factory.register(webSocketClass);
			}
		});
		return ws;
	}

	public static void main(final String[] args) throws Exception {
		final Server server = initServer2(initConfig(), initSSLFactory());
		server.setHandler(initHandlers());
		server.start();
		LOG.info(server.dump());
		if (Desktop.isDesktopSupported()) {
			Desktop.getDesktop().browse(new URI("https://localhost:" + SERVER_PORT));
		}
		server.join();
	}
}
