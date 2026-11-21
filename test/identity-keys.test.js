import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { identityKeyProofMessage, identityKeyTransitionMessage, verifyIdentityKeyProof, verifyIdentityKeyTransition } from "../worker/identity-keys.js";

const b64 = (bytes) => Buffer.from(bytes).toString("base64");

test("verifies an ECDSA proof binding an account ID to its ECDH identity key", async () => {
  const ecdh = await webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const signing = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const identityPublicKey = b64(await webcrypto.subtle.exportKey("raw", ecdh.publicKey));
  const identitySigningPublicKey = b64(await webcrypto.subtle.exportKey("raw", signing.publicKey));
  const signature = b64(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signing.privateKey, identityKeyProofMessage("hugo_test", identityPublicKey)));
  const proof = { userId: "hugo_test", identityPublicKey, identitySigningPublicKey, identityKeySignature: signature };
  assert.equal(await verifyIdentityKeyProof(proof), true);
  assert.equal(await verifyIdentityKeyProof({ ...proof, userId: "another_user" }), false);
  assert.equal(await verifyIdentityKeyProof({ ...proof, identityPublicKey: b64(new Uint8Array(65).fill(4)) }), false);
  assert.equal(await verifyIdentityKeyProof({ ...proof, identityKeySignature: b64(new Uint8Array(64)) }), false);
});

test("rejects malformed proof input without throwing", async () => {
  assert.equal(await verifyIdentityKeyProof({ userId: "invalid id", identityPublicKey: "", identitySigningPublicKey: "", identityKeySignature: "" }), false);
});


test("verifies a key rotation signed by the previous account identity", async () => {
  const previous = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const nextEcdh = await webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const nextSigning = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const previousSigningPublicKey = b64(await webcrypto.subtle.exportKey("raw", previous.publicKey));
  const identityPublicKey = b64(await webcrypto.subtle.exportKey("raw", nextEcdh.publicKey));
  const identitySigningPublicKey = b64(await webcrypto.subtle.exportKey("raw", nextSigning.publicKey));
  const message = identityKeyTransitionMessage("hugo_test", previousSigningPublicKey, identityPublicKey, identitySigningPublicKey);
  const identityTransitionSignature = b64(await webcrypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, previous.privateKey, message
  ));
  const transition = {
    userId: "hugo_test",
    previousSigningPublicKey,
    identityPublicKey,
    identitySigningPublicKey,
    identityTransitionSignature
  };
  assert.equal(await verifyIdentityKeyTransition(transition), true);
  assert.equal(await verifyIdentityKeyTransition({ ...transition, userId: "another_user" }), false);
  assert.equal(await verifyIdentityKeyTransition({ ...transition, identityPublicKey: b64(new Uint8Array(65).fill(4)) }), false);
});
