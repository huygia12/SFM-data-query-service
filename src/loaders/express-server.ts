import express from "express";
import {Server} from "node:http";
import cors from "cors";
import {options} from "@/common/cors-config";
import errorHandler from "@/errors/error-handler";
import "express-async-errors";
import {API_v1} from "@/routes";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import helmet from "helmet";
import compression from "compression";

type ServerFactory = (app: express.Application) => Server;

class ExpressServer {
    private _app: express.Application;
    private _server: Server;

    public constructor(
        private readonly port: number,
        private readonly serverFactory: ServerFactory
    ) {
        this.listen();
    }

    private listen(): void {
        this._app = express();
        this._app.use(morgan("dev"));
        this._app.use(helmet());
        this._app.use(compression());
        this._app.use(cors(options));
        this._app.use(cookieParser());
        this._app.use(express.json());
        this._app.use("/", API_v1);
        this._app.use("*", errorHandler);

        this._server = this.serverFactory(this._app);

        this._server.listen(this.port, () => {
            console.info(
                `[express server]: Express server is running at port ${this.port}`
            );
        });
    }

    public close(): void {
        this._server.close((error) => {
            if (error) throw error;

            console.info("[express server]: Stopped");
        });
    }

    public getApp() {
        return this._app;
    }
}

export default ExpressServer;
