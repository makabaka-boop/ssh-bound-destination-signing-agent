import crypto from 'node:crypto';

export const AGENT_FAILURE = 5;
export const AGENT_SUCCESS = 6;
export const SSH2_AGENTC_REQUEST_IDENTITIES = 11;
export const SSH2_AGENT_IDENTITIES_ANSWER = 12;
export const SSH2_AGENTC_SIGN_REQUEST = 13;
export const SSH2_AGENT_SIGN_RESPONSE = 14;
export const SSH_AGENTC_EXTENSION = 27;
export const SSH_AGENT_EXTENSION_FAILURE = 28;
export const SSH_AGENT_EXTENSION_RESPONSE = 29;

export const ED25519_ALGORITHM = 'ssh-ed25519';
export const SESSION_BIND_EXTENSION = 'session-bind@openssh.com';
export const HOSTBOUND_METHOD = 'publickey-hostbound-v00@openssh.com';
export const SSH_CONNECTION_SERVICE = 'ssh-connection';
export const SSH_MSG_USERAUTH_REQUEST = 50;

export const MAX_MESSAGE = 256 * 1024;
export const MAX_SESSION_ID = 128;

export function u32(number) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(number >>> 0, 0);
  return buf;
}

export function string(buf) {
  const value = buf instanceof Buffer ? buf : Buffer.from(buf);
  return Buffer.concat([u32(value.length), value]);
}

export function cstring(value) {
  return string(Buffer.from(value, 'utf8'));
}

export function frame(message) {
  return string(message);
}

export function message(type, body = Buffer.alloc(0)) {
  return Buffer.concat([Buffer.from([type]), body]);
}

export function failure() {
  return message(AGENT_FAILURE);
}

export function success() {
  return message(AGENT_SUCCESS);
}

export function extensionFailure() {
  return message(SSH_AGENT_EXTENSION_FAILURE);
}

export class Reader {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
  }

  get remaining() {
    return this.buf.length - this.pos;
  }

  byte() {
    if (this.remaining < 1) throw new ParseError('missing byte');
    return this.buf[this.pos++];
  }

  boolean() {
    const value = this.byte();
    if (value !== 0 && value !== 1) throw new ParseError('invalid boolean');
    return value === 1;
  }

  uint32() {
    if (this.remaining < 4) throw new ParseError('missing uint32');
    const value = this.buf.readUInt32BE(this.pos);
    this.pos += 4;
    return value;
  }

  buffer() {
    const length = this.uint32();
    if (this.remaining < length) throw new ParseError('short string');
    const value = this.buf.subarray(this.pos, this.pos + length);
    this.pos += length;
    return Buffer.from(value);
  }

  rest() {
    const value = Buffer.from(this.buf.subarray(this.pos));
    this.pos = this.buf.length;
    return value;
  }

  cstring() {
    const value = this.buffer();
    try {
      return new TextDecoder('utf8', { fatal: true }).decode(value);
    } catch {
      throw new ParseError('invalid UTF-8 string');
    }
  }

  end() {
    if (this.remaining !== 0) throw new ParseError('trailing bytes');
  }
}

export class ParseError extends Error {}

export function encodeEdPublicKey(raw) {
  return Buffer.concat([cstring(ED25519_ALGORITHM), string(raw)]);
}

export function decodeEdPublicKeyBlob(blob) {
  try {
    const r = new Reader(blob);
    const algorithm = r.cstring();
    if (algorithm !== ED25519_ALGORITHM) throw new ParseError('unsupported key algorithm');
    const raw = r.buffer();
    r.end();
    if (raw.length !== 32) throw new ParseError('bad Ed25519 public key length');
    const keyObject = crypto.createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') },
      format: 'jwk',
    });
    return { raw, blob: Buffer.from(blob), keyObject };
  } catch (err) {
    if (err instanceof ParseError) throw err;
    throw new ParseError(`invalid Ed25519 public key: ${err.message}`);
  }
}

export function decodeEdSignatureBlob(signatureBlob) {
  const r = new Reader(signatureBlob);
  const algorithm = r.cstring();
  const raw = r.buffer();
  r.end();
  if (algorithm !== ED25519_ALGORITHM || raw.length !== 64) {
    throw new ParseError('invalid Ed25519 signature blob');
  }
  return raw;
}

export function encodeEdSignature(raw) {
  if (raw.length !== 64) throw new ParseError('bad Ed25519 signature length');
  return Buffer.concat([cstring(ED25519_ALGORITHM), string(raw)]);
}

export function verifyEd25519(publicKey, payload, signatureBlob) {
  let signature;
  try {
    signature = decodeEdSignatureBlob(signatureBlob);
  } catch {
    return false;
  }
  try {
    return crypto.verify(null, payload, publicKey, signature);
  } catch {
    return false;
  }
}

export function constantTimeBufferEquals(a, b) {
  const ba = Buffer.isBuffer(a) ? a : Buffer.from(a);
  const bb = Buffer.isBuffer(b) ? b : Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

export function constantTimeStringEquals(a, b) {
  return constantTimeBufferEquals(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}
