import Gun from "gun";

import "gun/lib/server.js";
import "gun/sea.js";

import { writeFile } from "node:fs/promises";

const { SEA } = Gun;

const relayPair = await SEA.pair();
const relayEncryptionPair = await SEA.pair();

const env = [
    `RELAY_PUB_KEY=${relayPair.pub}`,
    `RELAY_PRIV_KEY=${relayPair.priv}`,
    `RELAY_EPUB_KEY=${relayEncryptionPair.epub}`,
    `RELAY_EPRIV_KEY=${relayEncryptionPair.epriv}`,
    ""
].join("\n");

await writeFile(".env-generated", env, {
    encoding: "utf8",
    flag: "wx"
});

console.log("Generated relay keys in .env-generated");