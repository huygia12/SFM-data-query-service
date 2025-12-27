import crypto from "crypto";

const ALGORITHM = "aes-256-ctr";

function encrypt(
    plaintext: string,
    KEY: string
): {iv: string; ciphertext: string} {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
        ALGORITHM,
        Buffer.from(KEY, "hex"),
        iv
    );

    const encrypted = Buffer.concat([
        cipher.update(plaintext, "utf8"),
        cipher.final(),
    ]);
    return {
        iv: iv.toString("hex"),
        ciphertext: encrypted.toString("hex"),
    };
}

function decrypt(ciphertext: string, KEY: string, iv: string): string {
    const decipher = crypto.createDecipheriv(
        ALGORITHM,
        Buffer.from(KEY, "hex"),
        Buffer.from(iv, "hex")
    );

    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(ciphertext, "hex")),
        decipher.final(),
    ]);

    return decrypted.toString("utf8");
}

function getNewPrivateKey(): string {
    return crypto.randomBytes(32).toString("hex");
}

export default {
    encrypt,
    decrypt,
    getNewPrivateKey,
};
