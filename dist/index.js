import dotenv from 'dotenv';
dotenv.config();
import express from "express";
import http from "http";
import Gun from "gun";
import "gun/lib/server.js";
import "gun/sea.js";
import { createHash } from "node:crypto";
const { SEA } = Gun;
import Ajv from "ajv";
import { randomBytes } from "crypto";
import EquixModule from "./wasm/equix.js";
import { fuzzzAuthMessageSchema } from './types.js';
const Module = await EquixModule();
if (!Module._equix_init_verify()) {
    throw new Error("Equi-X initialization failed");
}
const app = express();
const server = http.createServer(app);
function requireEnv(name) {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}
const relayPair = {
    pub: requireEnv("RELAY_PUB_KEY"),
    priv: requireEnv("RELAY_PRIV_KEY"),
    epub: requireEnv("RELAY_EPUB_KEY"),
    epriv: requireEnv("RELAY_EPRIV_KEY")
};
const relayRegistry = new Map([
    [
        // Fuzzz's default network relay - uncomment this to pair with us.
        /*
        "no8VCVkIaUUVaRTGs8ORFTySTfE0ExaWTyC92ASP9yo.1OTlTL2zx3IadKZYwRaoasCyN35jGAAr5q5vzIxEjQg",
        {
            pub:"no8VCVkIaUUVaRTGs8ORFTySTfE0ExaWTyC92ASP9yo.1OTlTL2zx3IadKZYwRaoasCyN35jGAAr5q5vzIxEjQg",
            url:"https://relay.fuzzz.cloud/gun?fuzzz-relay=1"
        },*/
        // Replace with additional peer pubkey/urls, this is just an example
        "782GRP8zmzilKa6xeqGQtEc3EcWr0z7Oivhfg_f3yCw.QVrR5M6Q58FPmNCz8KmVo79iTU_chmKztGVBUXj-Jd0",
        {
            pub: "782GRP8zmzilKa6xeqGQtEc3EcWr0z7Oivhfg_f3yCw.QVrR5M6Q58FPmNCz8KmVo79iTU_chmKztGVBUXj-Jd0",
            url: "http://192.168.1.69:8766/gun?fuzzz-relay=1",
        }
    ]
]);
const bootstrapPeers = Array.from(relayRegistry.values(), relay => relay.url);
const powChallenges = new Map();
const relayByWire = new Map();
const cleanupAttached = new WeakSet();
const LIMITS = {
    maxDocumentBytes: 16_384,
    maxPoints: 1_024,
    maxPointDistance: 5.1,
    maxPowChallenges: 10_000,
    powLifetimeMs: 180_000,
    targetDifficulty: (2n ** 64n) >> 4n,
    relayAuthTimeoutMs: 15_000,
};
function cleanupPeer(peer) {
    if (!peer) {
        return;
    }
    const wire = peer.wire;
    if (wire) {
        const state = relayByWire.get(wire);
        if (state?.authTimeout) {
            clearTimeout(state.authTimeout);
        }
        relayByWire.delete(wire);
        cleanupAttached.delete(wire);
    }
}
function attachPeerCleanup(peer) {
    const wire = peer?.wire;
    if (!wire) {
        return;
    }
    if (cleanupAttached.has(wire)) {
        return;
    }
    cleanupAttached.add(wire);
    const cleanup = () => {
        cleanupPeer(peer);
    };
    wire.on("close", cleanup);
    wire.on("error", cleanup);
}
async function handleFuzzzAuth(msg, peer, state) {
    if (msg.type === "challenge-back") {
        const challenge = msg.challenge;
        if (typeof challenge !== "string" ||
            !challenge) {
            return;
        }
        try {
            const signature = await SEA.sign(challenge, relayPair);
            gun.back("opt.mesh").say({
                dam: "fuzzz-auth",
                type: "response-back",
                pub: relayPair.pub,
                signature
            }, peer);
        }
        catch (err) {
            console.error("Failed to sign challenge:", err);
            peer.wire?.close();
        }
        return;
    }
    if (msg.type === "challenge") {
        const challenge = msg.challenge;
        if (typeof challenge !== "string" ||
            !challenge) {
            return;
        }
        try {
            const signature = await SEA.sign(challenge, relayPair);
            gun.back("opt.mesh").say({
                dam: "fuzzz-auth",
                type: "response",
                pub: relayPair.pub,
                signature
            }, peer);
        }
        catch (err) {
            console.error("Failed to sign challenge:", err);
            peer.wire?.close();
        }
        return;
    }
    if (msg.type === "response") {
        const { pub, signature } = msg;
        if (typeof pub !== "string" ||
            typeof signature !== "string") {
            peer.wire?.close();
            return;
        }
        const challenge = state.remoteChallenge;
        if (!challenge) {
            return;
        }
        delete state.remoteChallenge;
        let verified;
        try {
            verified =
                await SEA.verify(signature, pub);
        }
        catch {
            peer.wire?.close();
            return;
        }
        if (verified !== challenge) {
            console.warn("Relay challenge mismatch:", peer.id, pub);
            peer.wire?.close();
            return;
        }
        if (!relayRegistry.has(pub)) {
            console.warn("Unknown relay:", pub);
            peer.wire?.close();
            return;
        }
        state.remoteAuthenticated = true;
        state.pub = pub;
        if (state.authTimeout) {
            clearTimeout(state.authTimeout);
            state.authTimeout = undefined;
        }
        delete state.remoteAuthenticating;
        return;
    }
    if (msg.type === "response-back") {
        const { pub, signature } = msg;
        if (typeof pub !== "string" ||
            typeof signature !== "string") {
            peer.wire?.close();
            return;
        }
        const challenge = state.challenge;
        if (!challenge) {
            return;
        }
        delete state.challenge;
        let verified;
        try {
            verified =
                await SEA.verify(signature, pub);
        }
        catch {
            peer.wire?.close();
            return;
        }
        if (verified !== challenge) {
            console.warn("Relay challenge mismatch:", peer.id, pub);
            peer.wire?.close();
            return;
        }
        if (!relayRegistry.has(pub)) {
            console.warn("Unknown relay:", pub);
            peer.wire?.close();
            return;
        }
        state.authenticated = true;
        state.pub = pub;
        if (state.authTimeout) {
            clearTimeout(state.authTimeout);
            state.authTimeout = undefined;
        }
        delete state.authenticating;
        return;
    }
}
function startRelayAuthTimeout(peer, state) {
    if (state.authTimeout) {
        clearTimeout(state.authTimeout);
    }
    state.authTimeout = setTimeout(() => {
        peer.wire?.close();
    }, LIMITS.relayAuthTimeoutMs);
}
function claimsRelayFromPeer(peer) {
    if (typeof peer?.url !== "string") {
        return false;
    }
    try {
        return new URL(peer.url)
            .searchParams
            .get("fuzzz-relay") === "1";
    }
    catch {
        return false;
    }
}
Gun.on("opt", function (root) {
    const opt = root.opt;
    const mesh = root.opt.mesh;
    const originalHi = mesh.hi;
    mesh.hi = function (peer) {
        const claimsRelay = claimsRelayFromPeer(peer);
        let state = relayByWire.get(peer.wire);
        if (!state) {
            state = {
                claimsRelay,
                authenticated: false,
            };
            relayByWire.set(peer.wire, state);
            attachPeerCleanup(peer);
        }
        if (claimsRelay) {
            // incoming node claims relay send challenge
            state.claimsRelay = true;
            if (!state.remoteAuthenticated &&
                !state.remoteAuthenticating) {
                state.remoteAuthenticated = false;
                state.remoteAuthenticating = true;
                startRelayAuthTimeout(peer, state);
                authenticateRemoteRelay(peer, state);
            }
        }
        return originalHi.call(this, peer);
    };
    this.to.next(root);
    const originalHear = mesh.hear;
    mesh.hear = function (raw, peer) {
        if (!peer) {
            return;
        }
        const wire = peer.wire;
        let state = wire
            ? relayByWire.get(peer.wire)
            : undefined;
        let parsed;
        try {
            if (typeof raw === "string") {
                parsed = JSON.parse(raw);
            }
            else if (raw !== null &&
                typeof raw === "object") {
                parsed = raw;
            }
            else {
                return;
            }
        }
        catch (error) {
            console.warn("Failed to parse mesh message:", error);
            return;
        }
        const messages = Array.isArray(parsed)
            ? parsed
            : [parsed];
        for (const message of messages) {
            if (message?.dam === 'fuzzz-pow') {
                if (!state) {
                    console.warn("Auth message from unknown peer:", peer.id);
                    continue;
                }
                if (message.type === "challenge-pow-request") {
                    respondToPowChallenge(peer, message.id);
                    continue;
                }
            }
            if (message?.dam === "fuzzz-auth") {
                if (!state) {
                    console.warn("Auth message from unknown peer:", peer.id);
                    continue;
                }
                if (!isFuzzzAuthMessage(message)) {
                    continue;
                }
                if (message.type === "challenge") {
                    state.claimsRelay = true;
                    if (!state.authenticated && !state.authenticating) {
                        // we are not authenticated 
                        state.authenticated = false;
                        state.authenticating = true;
                        startRelayAuthTimeout(peer, state);
                        authenticateRelay(peer, state);
                    }
                    handleFuzzzAuth(message, peer, state);
                    continue;
                }
                if (message.type === "challenge-back") {
                    handleFuzzzAuth(message, peer, state);
                    continue;
                }
                if (message.type === "response" || message.type === "response-back") {
                    handleFuzzzAuth(message, peer, state);
                    continue;
                }
            }
        }
        const result = originalHear.call(this, raw, peer);
        return result;
    };
    root.on("put", async function (msg) {
        let page = null;
        try {
            page = await validateIncomingPut(msg);
        }
        catch (err) {
            console.warn("Rejected Gun write:", err?.message ?? err);
            return;
        }
        this.to.next(msg);
        if (page)
            await refreshPostIndex(page);
    });
});
Gun.serve(app);
const gun = Gun({
    web: server,
    file: "data",
    peers: bootstrapPeers,
    multicast: false
});
/* for development
setTimeout(() => {
    console.log("🔥 FORCING OUTBOUND");

    gun.on("out", {
        dam: "hi"
    });
}, 1000);
*/
async function refreshPostIndex(page) {
    return new Promise((resolve) => {
        gun
            .get("@app")
            .get(page)
            .get("posts")
            .once((data) => {
            resolve(data);
        });
    });
}
function respondToPowChallenge(peer, id) {
    if (!peer?.wire) {
        return;
    }
    evictPowChallengesIfNeeded();
    const challenge = randomBytes(32).toString("hex");
    const expires = Date.now() + LIMITS.powLifetimeMs;
    const bucket = new Date()
        .toISOString()
        .slice(0, 10);
    const mesh = gun.back("opt.mesh");
    let out = {
        id,
        dam: "fuzzz-pow",
        type: "challenge-pow-response",
        challenge,
        expires,
        bucket: bucket,
        difficulty: LIMITS.targetDifficulty.toString()
    };
    powChallenges.set(challenge, {
        bucket: bucket,
        expires,
        postSeen: false,
        indexSeen: false
    });
    mesh.say(out, peer);
}
function authenticateRelay(peer, state) {
    if (!peer?.wire) {
        return;
    }
    const challenge = randomBytes(32).toString("hex");
    state.challenge = challenge;
    const mesh = gun.back("opt.mesh");
    let msg = {
        dam: "fuzzz-auth",
        type: "challenge-back",
        challenge
    };
    mesh.say(msg, peer);
}
function authenticateRemoteRelay(peer, state) {
    if (!peer?.wire) {
        return;
    }
    const challenge = randomBytes(32).toString("hex");
    state.remoteChallenge = challenge;
    const mesh = gun.back("opt.mesh");
    let msg = {
        dam: "fuzzz-auth",
        type: "challenge",
        challenge
    };
    mesh.say(msg, peer);
}
const ajv = new Ajv();
import { postSchema } from "./types.js";
const uploadValidator = ajv.compile(postSchema);
const fuzzzAuthValidator = ajv.compile(fuzzzAuthMessageSchema);
function isFuzzzAuthMessage(value) {
    return fuzzzAuthValidator(value);
}
function validateUpload(upload) {
    if (!uploadValidator(upload))
        return null;
    return upload;
}
// Restore numeric-keyed Gun objects back into arrays after reading.
function objectsToArrays(value) {
    if (!value || typeof value !== "object") {
        return value;
    }
    const keys = Object.keys(value);
    const isArray = keys.length > 0 &&
        keys.every((k, i) => String(i) === k);
    if (isArray) {
        return keys
            .sort((a, b) => Number(a) - Number(b))
            .map(k => objectsToArrays(value[k]));
    }
    const out = {};
    for (const [k, v] of Object.entries(value)) {
        out[k] = objectsToArrays(v);
    }
    return out;
}
const GUN_PUB_PATTERN = "[A-Za-z0-9_-]{43}\\.[A-Za-z0-9_-]{43}";
const GUN_USER_SOUL_REGEX = /^~[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/;
const GUN_ALIAS_SOUL_REGEX = /^~@[A-Za-z0-9_-]{1,64}$/;
const USER_ROOT_REGEX = /^~[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/;
const USER_POSTS_REGEX = /^~[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}\/posts$/;
const USER_POST_REGEX = new RegExp(`^~(${GUN_PUB_PATTERN})/posts/([a-f0-9]{64})$`);
const APP_ALL_ROOT_REGEX = /^@app\/all$/;
const APP_ALL_BUCKET_REGEX = /^@app\/all\/(\d{4}-\d{2}-\d{2})$/;
const APP_ALL_POST_REGEX = new RegExp(`^@app/all/(\\d{4}-\\d{2}-\\d{2})/(${GUN_PUB_PATTERN}):([a-f0-9]{64})$`);
const APP_ALL_POST_FIELD_REGEX = new RegExp(`^${GUN_PUB_PATTERN}:[a-f0-9]{64}$`);
const APP_ROOT_REGEX = /^@app$/;
const APP_PAGE_REGEX = /^@app\/([a-f0-9]{64})$/;
const APP_POSTS_REGEX = /^@app\/([a-f0-9]{64})\/posts$/;
function getGunLinkTarget(value) {
    if (!value || typeof value !== "object") {
        return null;
    }
    // Already-decoded Gun relation
    if (typeof value["#"] === "string") {
        return value["#"];
    }
    // Gun field wrapper
    if (value[":"] &&
        typeof value[":"] === "object" &&
        typeof value[":"]["#"] === "string") {
        return value[":"]["#"];
    }
    return null;
}
function getAppLinkTarget(value) {
    const target = value?.["#"];
    return typeof target === "string"
        ? target
        : null;
}
export function decodePoints(value) {
    if (typeof value !== "string") {
        throw new Error("Invalid points encoding");
    }
    let buffer;
    try {
        buffer = Buffer.from(value, "base64");
    }
    catch {
        throw new Error("Invalid base64 points");
    }
    if (buffer.length % 4 !== 0) {
        throw new Error("Invalid points length");
    }
    // Prevent someone from sending an enormous allocation/loop.
    if (buffer.length / 4 > LIMITS.maxPoints) {
        throw new Error("Too many points");
    }
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const points = [];
    for (let i = 0; i < buffer.length; i += 4) {
        const x = view.getInt16(i, true) / 10;
        const y = view.getInt16(i + 2, true) / 10;
        if (!Number.isFinite(x) || !Number.isFinite(y)) {
            throw new Error("Invalid point");
        }
        points.push({ x, y });
    }
    return points;
}
function isGunUserSoul(soul) {
    if (typeof soul !== "string") {
        return false;
    }
    return GUN_USER_SOUL_REGEX.test(soul);
}
function isGunAliasSoul(soul) {
    if (typeof soul !== "string") {
        return false;
    }
    return GUN_ALIAS_SOUL_REGEX.test(soul);
}
function decodeGunValue(rawValue) {
    if (typeof rawValue !== "string") {
        return rawValue;
    }
    try {
        return JSON.parse(rawValue);
    }
    catch {
        return rawValue;
    }
}
function evictPowChallengesIfNeeded() {
    if (powChallenges.size < LIMITS.maxPowChallenges) {
        return;
    }
    const oldest = powChallenges.keys().next().value;
    if (oldest !== undefined) {
        powChallenges.delete(oldest);
    }
}
function markPowSeen(challenge, type) {
    const state = powChallenges.get(challenge);
    if (!state) {
        return null;
    }
    if (type === "post") {
        state.postSeen = true;
    }
    else {
        state.indexSeen = true;
    }
    if (state.postSeen && state.indexSeen) {
        powChallenges.delete(challenge);
        return null;
    }
    return state;
}
async function validateIncomingPut(msg) {
    if (!msg.put) {
        throw new Error("Missing put");
    }
    // console.log('message: ', msg);
    const put = msg.put;
    const soul = put["#"];
    const field = put["."];
    const rawValue = put[":"];
    const value = decodeGunValue(rawValue);
    if (USER_ROOT_REGEX.test(soul) &&
        field === "posts") {
        const target = getGunLinkTarget(value);
        if (target !== `~${soul.slice(1)}/posts`) {
            throw new Error("Invalid posts relation");
        }
        return null;
    }
    if (isGunUserSoul(soul)) {
        if (typeof field !== "string") {
            throw new Error("Invalid Gun user field");
        }
        switch (field) {
            case "pub":
                if (typeof value !== "string" ||
                    !value) {
                    throw new Error("Invalid Gun pub");
                }
                // The value should correspond to the pub portion
                // of the user's soul.
                if (value !== soul.slice(1)) {
                    throw new Error("Pub does not match user soul");
                }
                return;
            case "epub":
                if (!value ||
                    typeof value !== "object" ||
                    typeof value[":"] !== "string" ||
                    typeof value["~"] !== "string") {
                    throw new Error("Invalid Gun epub");
                }
                return;
            case "alias":
                if (!value ||
                    typeof value !== "object" ||
                    typeof value[":"] !== "string" ||
                    typeof value["~"] !== "string") {
                    throw new Error("Invalid Gun alias");
                }
                return;
            case "auth":
                if (!value ||
                    typeof value !== "object" ||
                    typeof value[":"] !== "string" ||
                    typeof value["~"] !== "string") {
                    throw new Error("Invalid Gun auth");
                }
                return;
            default:
                throw new Error(`Invalid Gun user field: ${field}`);
        }
    }
    if (isGunAliasSoul(soul)) {
        if (typeof field !== "string" ||
            !GUN_USER_SOUL_REGEX.test(field)) {
            throw new Error("Invalid Gun alias reference");
        }
        if (!value ||
            typeof value !== "object" ||
            value["#"] !== field) {
            throw new Error("Invalid Gun alias reference");
        }
        return null;
    }
    if (APP_ROOT_REGEX.test(soul) &&
        /^[a-f0-9]{64}$/.test(field)) {
        const target = getAppLinkTarget(value);
        if (target !== `@app/${field}`) {
            throw new Error("Invalid page reference");
        }
        return null;
    }
    if (APP_PAGE_REGEX.test(soul) &&
        field === "posts") {
        const target = getAppLinkTarget(value);
        const [, page] = soul.match(APP_PAGE_REGEX);
        const expected = `@app/${page}/posts`;
        if (target !== expected) {
            throw new Error("Invalid posts reference");
        }
        return null;
    }
    if (APP_POSTS_REGEX.test(soul) &&
        /^[^/]+$/.test(field)) {
        if (value !== true) {
            throw new Error("Invalid post index value");
        }
        return null;
    }
    if (APP_ROOT_REGEX.test(soul) &&
        field === "all") {
        return null;
    }
    if (APP_ALL_ROOT_REGEX.test(soul) &&
        typeof field === "string" &&
        APP_ALL_BUCKET_REGEX.test(`@app/all/${field}`)) {
        const target = getAppLinkTarget(value);
        if (target !== `@app/all/${field}`) {
            throw new Error("Invalid app all bucket reference");
        }
        return null;
    }
    if (APP_ALL_BUCKET_REGEX.test(soul) &&
        typeof field === "string" &&
        APP_ALL_POST_FIELD_REGEX.test(field)) {
        const target = getGunLinkTarget(value);
        if (target !== `${soul}/${field}`) {
            throw new Error("Invalid app all post reference");
        }
        return null;
    }
    if (APP_ALL_BUCKET_REGEX.test(soul)) {
        const [, bucket] = soul.match(APP_ALL_BUCKET_REGEX);
        const date = new Date(`${bucket}T00:00:00.000Z`);
        if (Number.isNaN(date.getTime()) ||
            date.toISOString().slice(0, 10) !== bucket) {
            throw new Error("Invalid bucket date");
        }
        return null;
    }
    if (typeof soul !== "string") {
        throw new Error(`Invalid soul ${JSON.stringify(msg)}`);
    }
    if (USER_POSTS_REGEX.test(soul) &&
        /^[a-f0-9]{64}$/.test(field)) {
        const target = getGunLinkTarget(value);
        const expected = `${soul}/${field}`;
        if (target !== expected) {
            throw new Error("Invalid page relation");
        }
        return null;
    }
    const indexingMatch = soul.match(APP_ALL_POST_REGEX);
    if (indexingMatch) {
        const [, bucket, pub, page] = indexingMatch;
        if (field !== "document") {
            throw new Error("Invalid app all field");
        }
        const data = value; //JSON.parse(value[':']);
        if (data._pub !== pub) {
            throw new Error("Pub mismatch");
        }
        const indexDocument = await verifySignature(data);
        if (!indexDocument) {
            throw new Error("Invalid Signature");
        }
        if (typeof indexDocument !== "object" ||
            indexDocument === null) {
            throw new Error("Invalid app all document");
        }
        const doc = indexDocument;
        if (typeof doc.url !== "string" || !doc.url) {
            throw new Error("Invalid app all URL");
        }
        if (doc.url.length > 2048) {
            throw new Error("URL exceeds maximum length");
        }
        try {
            const url = new URL(doc.url);
            if (url.protocol !== "http:" &&
                url.protocol !== "https:") {
                throw new Error("Invalid URL protocol");
            }
        }
        catch {
            throw new Error("Invalid URL");
        }
        if (typeof doc.challenge !== "string" ||
            !doc.challenge) {
            throw new Error("Invalid app all challenge");
        }
        const expectedPage = createHash("sha256")
            .update(doc.url, "utf8")
            .digest("hex");
        if (expectedPage !== page) {
            throw new Error("URL does not match post page hash");
        }
        const challenge = powChallenges.get(doc.challenge);
        if (!challenge) {
            throw new Error("Unknown PoW challenge");
        }
        if (Date.now() > challenge.expires) {
            powChallenges.delete(doc.challenge);
            throw new Error("PoW challenge expired");
        }
        if (challenge.bucket !== bucket) {
            throw new Error("PoW challenge bucket mismatch");
        }
        markPowSeen(doc.challenge, "index");
        return null;
    }
    const userPostMatch = soul.match(USER_POST_REGEX);
    if (userPostMatch) {
        const [, pub, page] = userPostMatch;
        if (field !== "document") {
            throw new Error("Invalid user post field");
        }
        const bytes = Buffer.byteLength(value[":"]);
        if (bytes > LIMITS.maxDocumentBytes) {
            throw new Error("document exceeds 2KB");
        }
        const data = JSON.parse(value[':']);
        const solution = data.pow.solution;
        if (!Array.isArray(solution) ||
            solution.length !== 8 ||
            !solution.every((value) => typeof value === "number" &&
                Number.isInteger(value) &&
                value >= 0 &&
                value <= 0xffff)) {
            throw new Error("invalid pow solution");
        }
        const parts = data.pow.pattern.split(':');
        // parts[0] challenge random bytes
        // parts[1] pubkey 
        // parts[2] expiry
        // parts[3] nonce
        if (parts.length !== 4) {
            throw new Error("invalid pow");
        }
        const powChallenge = powChallenges.get(data.pow.challenge);
        if (!powChallenge) {
            throw new Error("invalid pow, unknown challenge");
        }
        const expires = Number(parts[2]);
        if (!Number.isSafeInteger(expires)) {
            throw new Error("invalid pow expiry");
        }
        if (Date.now() > expires) {
            powChallenges.delete(data.pow.challenge);
            throw new Error("invalid pow, expired");
        }
        if (expires !== powChallenge.expires) {
            throw new Error("invalid pow, expiry mismatch");
        }
        if (parts[0] !== page) {
            throw new Error("invalid pow, mismatched page");
        }
        if (parts[1] !== pub) {
            throw new Error("invalid pow, mismatched public key");
        }
        const pattern = data.pow.pattern;
        // Convert pattern to UTF-8 bytes
        const challengeBytes = new TextEncoder().encode(pattern);
        // Allocate challenge in WASM memory
        const challengePtr = Module._malloc(challengeBytes.length);
        Module.HEAPU8.set(challengeBytes, challengePtr);
        // Allocate space for equix_solution
        const solutionPtr = Module._malloc(16);
        // Write the 8 uint16 values into the solution struct
        const solutionView = new Uint16Array(Module.HEAPU8.buffer, solutionPtr, 8);
        solutionView.set(solution);
        try {
            const result = Module._equix_verify_wrapper(challengePtr, challengeBytes.length, solutionPtr);
            if (result !== 0) {
                throw new Error("invalid pow, failed verification");
            }
        }
        finally {
            Module._free(challengePtr);
            Module._free(solutionPtr);
        }
        const encoded = await verifySignature(data);
        if (!encoded) {
            throw new Error("Invalid Signature");
        }
        let document;
        try {
            document = decodeURIComponent(escape(atob(encoded)));
        }
        catch (err) {
            console.warn("Invalid encoded document:", err);
            throw new Error("Invalid document encoding");
        }
        let parsed;
        try {
            parsed = JSON.parse(document);
        }
        catch (err) {
            console.warn("Invalid parse: ", err);
            throw new Error("Invalid JSON");
        }
        let arrayified = objectsToArrays(parsed);
        if (arrayified.payload.drawing !== "stub") {
            for (const stroke of arrayified.payload.drawing.strokes) {
                stroke.points = decodePoints(stroke.points);
            }
        }
        const post = validateUpload(arrayified);
        if (!post) {
            throw new Error("Invalid post");
        }
        if (post._protocol.version !== 1) {
            throw new Error("Unsupported protocol");
        }
        if (post._pub !== pub) {
            throw new Error("Pub mismatch");
        }
        if (post._page !== page) {
            throw new Error("Page mismatch");
        }
        if (typeof post.url !== "string" || !post.url) {
            throw new Error("Invalid app all URL");
        }
        if (post.url.length > 2048) {
            throw new Error("URL exceeds maximum length");
        }
        try {
            const url = new URL(post.url);
            if (url.protocol !== "http:" &&
                url.protocol !== "https:") {
                throw new Error("Invalid URL protocol");
            }
        }
        catch {
            throw new Error("Invalid URL");
        }
        if (post.payload.drawing !== "stub") {
            const totalPoints = post.payload.drawing.strokes.reduce((sum, stroke) => sum + stroke.points.length, 0);
            if (totalPoints > LIMITS.maxPoints) {
                throw new Error("Point limit exceeded");
            }
            let inkCost = 0;
            for (const stroke of post.payload.drawing.strokes) {
                let length = 0;
                const points = stroke.points;
                for (let i = 1; i < points.length; i++) {
                    const dx = points[i].x - points[i - 1].x;
                    const dy = points[i].y - points[i - 1].y;
                    const distance = Math.hypot(dx, dy);
                    if (distance > LIMITS.maxPointDistance) {
                        throw new Error("Point gap too large");
                    }
                    length += distance;
                }
                /*
                inkCost += length * stroke.width;
        
                if (inkCost > MAX_INK) {
                    console.log('invalid ink budget')
                    throw new Error("Drawing exceeds ink budget");
                }*/
            }
        }
        if (post.payload.texts !== "stub") {
            if (post.payload.texts.length > 8) {
                throw new Error("Max text items exceeded");
            }
            for (const text of post.payload.texts) {
                if (text.content.length > 512) {
                    throw new Error("Text item exceeds max length");
                }
            }
        }
        markPowSeen(data.pow.challenge, "post");
        return page;
    }
    throw new Error(`Invalid soul ${JSON.stringify(msg)}`);
}
async function verifySignature(doc) {
    if (!doc ||
        typeof doc !== "object" ||
        typeof doc._sig !== "string" ||
        typeof doc._pub !== "string") {
        return null;
    }
    const sig = doc._sig;
    const pub = doc._pub;
    try {
        const verified = await SEA.verify(sig, pub);
        return verified || null;
    }
    catch (err) {
        console.error("SEA VERIFY ERROR:", err);
        return null;
    }
}
const PORT = process.env.GUN_PORT;
server.listen(Number(PORT), "0.0.0.0");
//# sourceMappingURL=index.js.map