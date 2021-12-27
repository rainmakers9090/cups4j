package org.cups4j.operations;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContexts;
import org.cups4j.CupsAuthentication;
import org.cups4j.CupsPrinter;
import org.cups4j.CupsSSL;

import javax.net.ssl.SSLContext;

public final class IppHttp {

	private static final int MAX_CONNECTION_BUFFER = 20;

	private static final int CUPSTIMEOUT = Integer.parseInt(System.getProperty("cups4j.timeout", "10000"));

	private static final RequestConfig requestConfig = RequestConfig.custom()
			.setSocketTimeout(CUPSTIMEOUT).setConnectTimeout(CUPSTIMEOUT)
			.build();

	private static final CloseableHttpClient client = HttpClientBuilder.create()
			.disableCookieManagement()
			.disableRedirectHandling()
			.evictExpiredConnections()
			.setMaxConnPerRoute(MAX_CONNECTION_BUFFER)
			.setMaxConnTotal(MAX_CONNECTION_BUFFER)
			.setRetryHandler(new DefaultHttpRequestRetryHandler())
			.build();

	private static final CloseableHttpClient httpsClient = HttpClientBuilder.create()
			.disableCookieManagement()
			.disableRedirectHandling()
			.setHostnameVerifier(SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)
			.evictExpiredConnections()
			.setMaxConnPerRoute(MAX_CONNECTION_BUFFER)
			.setMaxConnTotal(MAX_CONNECTION_BUFFER)
			.setRetryHandler(new DefaultHttpRequestRetryHandler())
			.build();

	private IppHttp() {
	}

	public static CloseableHttpClient createHttpClient()
	{
		return client;
	}

	public static CloseableHttpClient createHttpsClient(CupsSSL cupsSSL) throws Exception
	{
		KeyStore keyStore = null;
		try (InputStream keyStoreStream = IppHttp.class.getClassLoader().getResourceAsStream(cupsSSL.getKeyStorePath()))
		{
			keyStore = KeyStore.getInstance("JKS"); // or "PKCS12"
			keyStore.load(keyStoreStream, cupsSSL.getKeyStorePass().toCharArray());
		}

		SSLContext sslContext = SSLContexts.custom()
				.loadKeyMaterial(keyStore ,  cupsSSL.getKeyPass().toCharArray()) // use null as second param if you don't have a separate key password
				.build();

		final CloseableHttpClient httpsClient = HttpClientBuilder.create()
				.disableCookieManagement()
				.disableRedirectHandling()
				.setHostnameVerifier(SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)
				.setSSLContext(sslContext)
				.evictExpiredConnections()
				.setMaxConnPerRoute(MAX_CONNECTION_BUFFER)
				.setMaxConnTotal(MAX_CONNECTION_BUFFER)
				.setRetryHandler(new DefaultHttpRequestRetryHandler())
				.build();

		return httpsClient;
	}

	public static void setHttpHeaders(HttpPost httpPost, CupsPrinter targetPrinter,
			CupsAuthentication creds) {
		 if (targetPrinter == null) {
			 httpPost.addHeader("target-group", "local");
		 } else {
		 	 httpPost.addHeader("target-group", targetPrinter.getName());
		 }
	   httpPost.setConfig(requestConfig);

	   if (creds != null && StringUtils.isNotBlank(creds.getUserid())
	    		&& StringUtils.isNotBlank(creds.getPassword())) {
		    String auth = creds.getUserid() + ":" + creds.getPassword();
		    byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(StandardCharsets.ISO_8859_1));
		    String authHeader = "Basic " + new String(encodedAuth);
		    httpPost.setHeader(HttpHeaders.AUTHORIZATION, authHeader);
	   }
	}
}
