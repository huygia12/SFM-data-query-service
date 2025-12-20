import dotenv from "dotenv";
import {resolve} from "path";

type Config = {
    HTTP_PORT: number;
    HTTPS_PORT: number;
    AT_KEY: string;
    RT_KEY: string;
    OTP_KEY: string;
    EMAIL: string;
    GMAIL_PASSWORD: string;
    NODE_ENV: string;
    SSL_KEY_PATH: string | undefined;
    SSL_CERT_PATH: string | undefined;
};

const envConfig = dotenv.config({
    path: resolve(".env") as string,
});

if (envConfig.error) {
    console.error("[app-config]: Cannot find .env file");
} else {
    console.info("[app-config]: Using .env file to load environment variables");
}

const config: Config = {
    HTTP_PORT: parseInt(process.env.HTTP_PORT || "4000", 10),
    HTTPS_PORT: parseInt(process.env.HTTPS_PORT || "3443", 10),
    AT_KEY: `${process.env.AT_SECRET_KEY}`,
    RT_KEY: `${process.env.RT_SECRET_KEY}`,
    OTP_KEY: `${process.env.OTP_SECRET_KEY}`,
    EMAIL: `${process.env.EMAIL}`,
    GMAIL_PASSWORD: `${process.env.GMAIL_PASSWORD}`,
    NODE_ENV: `${process.env.NODE_ENV || "development"}`,
    SSL_KEY_PATH: process.env.SSL_KEY_PATH
        ? resolve(process.env.SSL_KEY_PATH)
        : undefined,
    SSL_CERT_PATH: process.env.SSL_CERT_PATH
        ? resolve(process.env.SSL_CERT_PATH)
        : undefined,
};

if (!config.AT_KEY || !config.RT_KEY) {
    throw new Error("[app-config]: secret key is required");
}

if (
    config.NODE_ENV == "development" &&
    (!config.SSL_KEY_PATH || !config.SSL_CERT_PATH)
) {
    throw new Error("[app-config]: SSL config is required in production mode");
}

export default config;
