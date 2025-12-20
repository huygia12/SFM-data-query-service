import config from "@/common/app-config";
import ExpressServer from "./express-server";
import http from "node:http";
import https from "node:https";
import fs from "fs";

export default () => {
    let expressServer: ExpressServer;

    if (config.NODE_ENV == "production") {
        const httpsOptions = {
            key: fs.readFileSync(config.SSL_KEY_PATH!),
            cert: fs.readFileSync(config.SSL_CERT_PATH!),
        };

        expressServer = new ExpressServer(config.HTTPS_PORT, (app) =>
            https.createServer(httpsOptions, app)
        );

        console.info("🔐 HTTPS enabled");
    } else {
        expressServer = new ExpressServer(config.HTTP_PORT, (app) =>
            http.createServer(app)
        );

        console.info("🌐 HTTP enabled");
    }

    process
        .on("exit", () => {
            expressServer.close();
        })
        .on("SIGINT", () => {
            expressServer.close();
        });
};
