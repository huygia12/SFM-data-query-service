const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

try {
    const certPath = path.resolve(__dirname, "ssl/cert.pem");
    console.log("Using cert path:", certPath);

    if (!fs.existsSync(certPath)) {
        throw new Error("cert.pem NOT FOUND");
    }

    const cert = fs.readFileSync(certPath);
    console.log("cert.pem loaded, size =", cert.length);

    const publicKey = crypto.createPublicKey(cert).export({
        type: "spki",
        format: "der",
    });

    const hash = crypto.createHash("sha256").update(publicKey).digest("base64");

    console.log("✅ RESULT:");
    console.log("sha256/" + hash);
} catch (err) {
    console.error("❌ ERROR:");
    console.error(err.message);
}
