package fr.dboissin.email;

import fr.dboissin.email.controller.EmailController;
import fr.wseduc.webutils.Server;
import org.vertx.java.core.file.FileSystem;
import org.vertx.java.core.json.JsonArray;
import org.vertx.java.core.json.JsonObject;

public class EmailProxy extends Server {

	@Override
	public void start() {
		FileSystem fs = vertx.fileSystem();
		if (fs.existsSync("mod.json")) {
			config = new JsonObject(fs.readFileSync("mod.json").toString("UTF-8"));
		}
		super.start();
		deployModules(config.getArray("modules", new JsonArray()));
		addController(new EmailController());
	}

	private void deployModules(JsonArray modules) {
		for (Object o : modules) {
			if (!(o instanceof JsonObject)) continue;
			JsonObject module = (JsonObject) o;
			if (module.getString("name") == null) {
				continue;
			}
			JsonObject conf = module.getObject("config", new JsonObject());
			container.deployModule(module.getString("name"),
					conf, module.getInteger("instances", 1));
		}
	}

}
