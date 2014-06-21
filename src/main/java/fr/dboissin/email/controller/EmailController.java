package fr.dboissin.email.controller;

import fr.dboissin.email.exception.ValidationException;
import fr.dboissin.email.util.Recaptcha;
import fr.wseduc.rs.Post;
import fr.wseduc.webutils.http.BaseController;
import fr.wseduc.webutils.request.RequestUtils;
import fr.wseduc.webutils.security.SecuredAction;
import org.vertx.java.core.Handler;
import org.vertx.java.core.Vertx;
import org.vertx.java.core.eventbus.Message;
import org.vertx.java.core.http.HttpServerRequest;
import org.vertx.java.core.http.RouteMatcher;
import org.vertx.java.core.json.JsonArray;
import org.vertx.java.core.json.JsonObject;
import org.vertx.java.platform.Container;

import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class EmailController extends BaseController {

	private Recaptcha recaptcha;

	@Override
	public void init(Vertx vertx, Container container, RouteMatcher rm, Map<String, SecuredAction> securedActions) {
		super.init(vertx, container, rm, securedActions);
		recaptcha = new Recaptcha(vertx, container.config().getBoolean("ssl", false));
	}

	@Post("")
	public void proxyEmail(final HttpServerRequest request) {
		String host = request.headers().get("Host");
		if (log.isDebugEnabled()) {
			log.debug("Host: " + host);
		}
		final JsonObject hostConfig = container.config()
				.getObject("host-mapping", new JsonObject()).getObject(host);
		if (hostConfig == null) {
			badRequest(request, "host.mapping.not.found");
			return;
		}
		JsonArray allowedReferer = hostConfig.getArray("allowed-referer");
		if (allowedReferer != null && allowedReferer.size() > 0) {
			String referer = request.headers().get("Referer");
			if (referer == null || !allowedReferer.contains(referer)) {
				unauthorized(request);
				return;
			}
		}
		RequestUtils.bodyToJson(request, new Handler<JsonObject>() {
			@Override
			public void handle(final JsonObject object) {
				String recaptchaPrivateKey = hostConfig.getString("recaptcha-private-key");
				if (recaptchaPrivateKey != null) {
					verifyCaptcha(request, recaptchaPrivateKey, object, new Handler<Boolean>() {
						@Override
						public void handle(Boolean isValid) {
							if (Boolean.TRUE.equals(isValid)) {
								validateAndSend(object, hostConfig, request);
							} else {
								badRequest(request, "invalid.captcha");
							}
						}
					});
				} else {
					validateAndSend(object, hostConfig, request);
				}
			}
		});
	}

	private void verifyCaptcha(HttpServerRequest request, String privateKey, JsonObject object,
			final Handler<Boolean> handler) {
		String remoteIp = request.headers().get("X-Real-IP");
		if (remoteIp == null) {
			remoteIp = request.headers().get("X-Forwarded-For");
			if (remoteIp == null) {
				remoteIp = request.remoteAddress().getHostName();
			}
		}
		if (log.isDebugEnabled()) {
			log.debug("Remote ip : " + remoteIp);
		}
		recaptcha.verify(privateKey, remoteIp,
				object.getString("recaptcha_challenge_field"),
				object.getString("recaptcha_response_field"),
				handler);
	}

	private void validateAndSend(JsonObject object, JsonObject hostConfig, final HttpServerRequest request) {
		try {
			validate(object, hostConfig);
		} catch (ValidationException e) {
			if (log.isDebugEnabled()) {
				log.debug("Validation error in object " + object.encode(), e);
			}
			badRequest(request, e.getMessage());
			return;
		}
		send(
				request,
				object.getString("from", hostConfig.getString("from")),
				object.getArray("to", hostConfig.getArray("to")),
				object.getArray("cc", hostConfig.getArray("cc")),
				object.getArray("bcc", hostConfig.getArray("bcc")),
				object.getString("subject", hostConfig.getString("subject")),
				object,
				object.getString("template", hostConfig.getString("template")),
				new Handler<Message<JsonObject>>() {
					@Override
					public void handle(Message<JsonObject> message) {
						if (message == null) {
							renderError(request);
						} else if ("ok".equals(message.body().getString("status"))) {
							renderJson(request, new JsonObject());
						} else {
							renderError(request, message.body());
						}
					}
				}
		);
	}

	private void validate(JsonObject object, JsonObject hostConfig) throws ValidationException {
		Set<String> fieldNames = new HashSet<>(object.getFieldNames());
		JsonObject fields = hostConfig.getObject("fields", new JsonObject());
		for (String n : fieldNames) {
			String regexField = fields.getString(n);
			if (regexField == null || object.getString(n) == null || object.getString(n).isEmpty()) {
				object.removeField(n);
			} else if (!regexField.isEmpty() && !object.getString(n).matches(regexField)) {
				throw new ValidationException("invalid." + n);
			}
		}
		Map<String, Object> m = object.toMap();
		for (Object o : hostConfig.getArray("required")) {
			if (!m.containsKey(o.toString())) {
				throw new ValidationException("missing." + o.toString());
			}
		}
	}

	private void send(HttpServerRequest request, String from, JsonArray to, JsonArray cc, JsonArray bcc,
			String subject, JsonObject object, String template, final Handler<Message<JsonObject>> handler) {
		final JsonObject json = new JsonObject()
				.putArray("to", to)
				.putString("from", from)
				.putArray("cc", cc)
				.putArray("bcc", bcc)
				.putString("subject", subject);
		processTemplate(request, template, object, new Handler<String>() {
			@Override
			public void handle(String body) {
				if (body != null) {
					try {
						log.debug(body);
						json.putString("body", new String(body.getBytes("UTF-8"), "ISO-8859-1"));
						eb.send("email", json, handler);
					} catch (UnsupportedEncodingException e) {
						log.error(e.getMessage(), e);
						handler.handle(null);
					}
				} else {
					log.error("Message is null.");
					handler.handle(null);
				}
			}
		});
	}

}
