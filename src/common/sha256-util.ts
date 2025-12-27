import crypto from "crypto";
import config from "./app-config";

export function sha256(input: string) {
    return crypto
        .createHash("sha256")
        .update(input + config.AES_SALT)
        .digest("hex");
}
