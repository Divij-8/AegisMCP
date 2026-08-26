import { buildApp } from "./app.js";
import { config } from "./config/index.js";

const app = buildApp();

const start = async () => {
  try {
    await app.listen({ port: config.port, host: config.host });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();
