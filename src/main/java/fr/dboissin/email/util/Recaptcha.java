package fr.dboissin.email.util;

import org.vertx.java.core.Handler;
import org.vertx.java.core.Vertx;
import org.vertx.java.core.buffer.Buffer;
import org.vertx.java.core.http.HttpClient;
import org.vertx.java.core.http.HttpClientRequest;
import org.vertx.java.core.http.HttpClientResponse;
import org.vertx.java.core.logging.Logger;
import org.vertx.java.core.logging.impl.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class Recaptcha {

	private final HttpClient httpClient;
	private static final Logger log = LoggerFactory.getLogger(Recaptcha.class);

	public Recaptcha(Vertx vertx, boolean ssl) {
		this.httpClient = vertx.createHttpClient()
				.setHost("www.google.com")
				.setPort(ssl ? 443 : 80)
				.setSSL(ssl)
				.setMaxPoolSize(16)
				.setKeepAlive(false);
	}

	public void verify(String privateKey, String remoteIp, String challenge, String response,
			final Handler<Boolean> handler) {
		HttpClientRequest r = httpClient.post("/recaptcha/api/verify", new Handler<HttpClientResponse>() {
			@Override
			public void handle(HttpClientResponse response) {
				response.bodyHandler(new Handler<Buffer>() {
					@Override
					public void handle(Buffer buffer) {
						String body = buffer.toString();
						log.debug(body);
						String [] lines = body.split("\\n");
						handler.handle("true".equals(lines[0]));
					}
				});
			}
		});
		r.putHeader("Content-type", "application/x-www-form-urlencoded");
		try {
			r.end("privatekey=" + URLEncoder.encode(privateKey, "UTF-8") +
					"&remoteip=" + URLEncoder.encode(remoteIp, "UTF-8") +
					"&challenge=" + URLEncoder.encode(challenge, "UTF-8") +
					"&response=" + URLEncoder.encode(response, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			log.error(e.getMessage(), e);
			handler.handle(false);
		}
	}

}
