import fs from 'node:fs';
import crypto from 'node:crypto';
import {
  ED25519_ALGORITHM,
  HOSTBOUND_METHOD,
  MAX_SESSION_ID,
  ParseError,
  Reader,
  SSH_CONNECTION_SERVICE,
  SSH_MSG_USERAUTH_REQUEST,
  constantTimeBufferEquals,
  constantTimeStringEquals,
  cstring,
  decodeEdPublicKeyBlob,
  string,
  verifyEd25519,
} from './protocol.js';

function loadEdPrivatePem(path) {
  const keyObject = crypto.createPrivateKey(fs.readFileSync(path));
  if (keyObject.asymmetricKeyType !== 'ed25519') {
    throw new Error(`user key at ${path} is not Ed25519`);
  }
  const jwk = keyObject.export({ format: 'jwk' });
  const raw = Buffer.from(jwk.x, 'base64url');
  if (raw.length !== 32) throw new Error('bad Ed25519 private key');
  const blob = Buffer.concat([cstring(ED25519_ALGORITHM), string(raw)]);
  return { keyObject, raw, blob, comment: 'restricted-demo' };
}

function loadEdSshPublicKey(path) {
  const line = fs.readFileSync(path, 'utf8')
    .split(/\r?\n/)
    .map((entry) => entry.trim())
    .find(Boolean);
  if (!line) throw new Error(`empty public key file: ${path}`);
  const fields = line.split(/\s+/);
  if (fields[0] !== ED25519_ALGORITHM || !fields[1]) {
    throw new Error(`${path} must contain an ${ED25519_ALGORITHM} public key`);
  }
  const blob = Buffer.from(fields[1], 'base64');
  return decodeEdPublicKeyBlob(blob);
}

export class RestrictedAgent {
  constructor({ userPrivateKeyPath, jumpPublicKeyPath, targetPublicKeyPath, targetUser }) {
    if (!targetUser || !Buffer.byteLength(targetUser, 'utf8')) {
      throw new Error('targetUser is required');
    }
    this.userKey = loadEdPrivatePem(userPrivateKeyPath);
    this.jumpHostKey = loadEdSshPublicKey(jumpPublicKeyPath);
    this.targetHostKey = loadEdSshPublicKey(targetPublicKeyPath);
    if (constantTimeBufferEquals(this.jumpHostKey.raw, this.targetHostKey.raw)) {
      throw new Error('jump and target host public keys must be different');
    }
    this.targetUser = targetUser;
  }

  createBinding() {
    return new ConnectionBinding(this);
  }

  identities() {
    return [{ blob: this.userKey.blob, comment: this.userKey.comment }];
  }

  parseHostboundAuthPayload(payload) {
    const outer = new Reader(payload);
    const sessionId = outer.buffer();
    const inner = new Reader(outer.rest());

    const type = inner.byte();
    const user = inner.cstring();
    const service = inner.cstring();
    const method = inner.cstring();
    const sigFollows = inner.boolean();
    const algorithm = inner.cstring();
    const userKeyBlob = inner.buffer();
    const hostKeyBlob = inner.buffer();
    inner.end();

    if (sessionId.length === 0 || sessionId.length > MAX_SESSION_ID) {
      throw new AuthorizationError('invalid session identifier in user authentication payload');
    }
    if (type !== SSH_MSG_USERAUTH_REQUEST) {
      throw new AuthorizationError('not an SSH_MSG_USERAUTH_REQUEST payload');
    }
    if (!constantTimeStringEquals(user, this.targetUser)) {
      throw new AuthorizationError('username is not authorized');
    }
    if (!constantTimeStringEquals(service, SSH_CONNECTION_SERVICE)) {
      throw new AuthorizationError('service is not ssh-connection');
    }
    if (!constantTimeStringEquals(method, HOSTBOUND_METHOD)) {
      throw new AuthorizationError('only host-bound public key authentication is accepted');
    }
    if (sigFollows !== true) {
      throw new AuthorizationError('public key request must have sig-follows=true');
    }
    if (!constantTimeStringEquals(algorithm, ED25519_ALGORITHM)) {
      throw new AuthorizationError('signature algorithm is not ssh-ed25519');
    }
    if (!constantTimeBufferEquals(userKeyBlob, this.userKey.blob)) {
      throw new AuthorizationError('embedded user public key is not the demo key');
    }
    if (!constantTimeBufferEquals(hostKeyBlob, this.targetHostKey.blob)) {
      throw new AuthorizationError('embedded target host key is not authorized');
    }

    // A blob comparison of hostKeyBlob plus a successful decode of userKeyBlob
    // prevents an unsupported encoding/key type from being accepted by
    // accident if the fixed blobs are ever replaced outside this demo.
    decodeEdPublicKeyBlob(hostKeyBlob);
    decodeEdPublicKeyBlob(userKeyBlob);

    return { sessionId, user, service, method, algorithm, userKeyBlob, hostKeyBlob };
  }
}

export class AuthorizationError extends Error {}

export class ConnectionBinding {
  constructor(agent) {
    this.agent = agent;
    // Exactly two hops are authorized: a forwarding jump host followed by a
    // non-forwarding target. The array is only appended after every check has
    // passed, so rejected binds cannot weaken or pollute an existing binding.
    this.hops = [];
  }

  bind({ hostKeyBlob, sessionId, signatureBlob, forwarding }) {
    if (sessionId.length === 0 || sessionId.length > MAX_SESSION_ID) {
      throw new AuthorizationError('invalid session identifier length');
    }
    if (this.hops.length >= 2) {
      throw new AuthorizationError('only jump and target bindings are permitted');
    }

    const expected = this.hops.length === 0 ? this.agent.jumpHostKey : this.agent.targetHostKey;
    const expectedForwarding = this.hops.length === 0;
    if (forwarding !== expectedForwarding) {
      throw new AuthorizationError(expectedForwarding
        ? 'the first binding must be the forwarding jump host'
        : 'the second binding must be the non-forwarding target');
    }
    if (!constantTimeBufferEquals(hostKeyBlob, expected.blob)) {
      throw new AuthorizationError(expectedForwarding
        ? 'host key is not the fixed jump host key'
        : 'host key is not the fixed target host key');
    }
    if (!verifyEd25519(expected.keyObject, sessionId, signatureBlob)) {
      throw new AuthorizationError('host key signature over session identifier is invalid');
    }
    if (this.hops.some((hop) => constantTimeBufferEquals(hop.sessionId, sessionId))) {
      throw new AuthorizationError('duplicate session identifier');
    }

    this.hops.push({
      hostKeyBlob: Buffer.from(hostKeyBlob),
      sessionId: Buffer.from(sessionId),
      forwarding,
    });
  }

  isComplete() {
    return this.hops.length === 2 &&
      this.hops[0].forwarding === true &&
      this.hops[1].forwarding === false;
  }

  authorizeSignature({ keyBlob, payload, flags }) {
    if (flags !== 0) {
      throw new AuthorizationError('unsupported signature flags');
    }
    if (!constantTimeBufferEquals(keyBlob, this.agent.userKey.blob)) {
      throw new AuthorizationError('requested key is not the demo user key');
    }
    if (!this.isComplete()) {
      throw new AuthorizationError('complete jump-to-target path binding is required');
    }

    const auth = this.agent.parseHostboundAuthPayload(payload);
    const target = this.hops[1];
    if (!constantTimeBufferEquals(auth.sessionId, target.sessionId)) {
      throw new AuthorizationError('payload session identifier is not the target binding');
    }
    if (!constantTimeBufferEquals(auth.hostKeyBlob, target.hostKeyBlob)) {
      throw new AuthorizationError('payload host key is not the target binding');
    }

    // The exact byte string presented by the client is signed only after the
    // structured fields and the target binding have both been checked. Never
    // reconstruct and sign a canonicalized copy: that would hide wire-format
    // differences in the actual authentication request.
    return Buffer.from(payload);
  }
}
