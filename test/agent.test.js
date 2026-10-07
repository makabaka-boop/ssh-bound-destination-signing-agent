import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  AGENT_FAILURE,
  AGENT_SUCCESS,
  ED25519_ALGORITHM,
  HOSTBOUND_METHOD,
  MAX_MESSAGE,
  SESSION_BIND_EXTENSION,
  SSH2_AGENTC_REQUEST_IDENTITIES,
  SSH2_AGENTC_SIGN_REQUEST,
  SSH2_AGENT_IDENTITIES_ANSWER,
  SSH2_AGENT_SIGN_RESPONSE,
  SSH_AGENTC_EXTENSION,
  SSH_AGENT_EXTENSION_FAILURE,
  SSH_AGENT_EXTENSION_RESPONSE,
  SSH_CONNECTION_SERVICE,
  SSH_MSG_USERAUTH_REQUEST,
  Reader,
  cstring,
  decodeEdSignatureBlob,
  frame,
  message,
  string,
} from '../src/protocol.js';
import { RestrictedAgent } from '../src/authorization.js';
import { generateDemoKeys } from '../scripts/generate-demo-keys.js';
import { startAgentServer } from '../src/agent.js';

async function makeFixtureAgent() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'restricted-agent-'));
  const keys = path.join(root, 'keys');
  await generateDemoKeys(keys);
  const agent = new RestrictedAgent({
    userPrivateKeyPath: path.join(keys, 'user_ed25519.pem'),
    jumpPublicKeyPath: path.join(keys, 'jump_host_ed25519.pub'),
    targetPublicKeyPath: path.join(keys, 'target_host_ed25519.pub'),
    targetUser: 'deploy',
  });
  return { root, keys, agent };
}

function loadPrivate(keys, name) {
  return crypto.createPrivateKey(fs.readFileSync(path.join(keys, `${name}_ed25519.pem`)));
}

function loadPublicBlob(keys, name) {
  const line = fs.readFileSync(path.join(keys, `${name}_ed25519.pub`), 'utf8')
    .trim()
    .split(/\s+/)[1];
  return Buffer.from(line, 'base64');
}

function signHostSession(privateKey, sessionId) {
  return Buffer.concat([
    cstring(ED25519_ALGORITHM),
    string(crypto.sign(null, sessionId, privateKey)),
  ]);
}

function bindExtension({ hostKey, sessionId, signature, forwarding }) {
  return message(
    SSH_AGENTC_EXTENSION,
    Buffer.concat([
      cstring(SESSION_BIND_EXTENSION),
      string(hostKey),
      string(sessionId),
      string(signature),
      Buffer.from([forwarding ? 1 : 0]),
    ]),
  );
}

function hostboundPayload({
  sessionId,
  user = 'deploy',
  service = SSH_CONNECTION_SERVICE,
  method = HOSTBOUND_METHOD,
  algorithm = ED25519_ALGORITHM,
  userKey,
  hostKey,
}) {
  return Buffer.concat([
    string(sessionId),
    Buffer.from([SSH_MSG_USERAUTH_REQUEST]),
    cstring(user),
    cstring(service),
    cstring(method),
    Buffer.from([1]),
    cstring(algorithm),
    string(userKey),
    string(hostKey),
  ]);
}

function signRequest(key, data, flags = 0) {
  const flagsBuf = Buffer.alloc(4);
  flagsBuf.writeUInt32BE(flags, 0);
  return message(SSH2_AGENTC_SIGN_REQUEST, Buffer.concat([
    string(key),
    string(data),
    flagsBuf,
  ]));
}

async function exchange(socketPath, request) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    const chunks = [];
    let timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('agent request timed out'));
    }, 5000);

    socket.on('connect', () => socket.write(frame(request)));
    socket.on('data', (chunk) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      if (buf.length < 4) return;
      const length = buf.readUInt32BE(0);
      if (buf.length < length + 4) return;
      clearTimeout(timer);
      socket.end();
      resolve(buf.subarray(4, length + 4));
    });
    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function exchangeRaw(socketPath, raw) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    const chunks = [];
    let timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('raw agent request timed out'));
    }, 5000);

    socket.on('connect', () => socket.end(raw));
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('end', () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks));
    });
    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function connectPair(socketPath) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });
}

function writeRequest(socket, request) {
  socket.write(frame(request));
}

function nextResponse(socket) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('pipelined response timed out'));
    }, 5000);

    const onData = (chunk) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      if (buf.length < 4) return;
      const length = buf.readUInt32BE(0);
      if (buf.length < length + 4) return;
      clearTimeout(timer);
      socket.off('data', onData);
      // This small test server processes requests serially, so unconsumed
      // pipelined bytes are not needed by the tests.
      resolve(buf.subarray(4, length + 4));
    };
    socket.on('data', onData);
    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

class PersistentAgent {
  constructor(socket) {
    this.socket = socket;
    this.queue = [];
    this.buffer = Buffer.alloc(0);
    this.socket.on('data', (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.drain();
    });
    this.socket.on('error', (err) => {
      const waiter = this.queue.shift();
      waiter?.reject(err);
    });
  }

  static async connect(socketPath) {
    return new PersistentAgent(await connectPair(socketPath));
  }

  drain() {
    while (this.queue.length > 0 && this.buffer.length >= 4) {
      const length = this.buffer.readUInt32BE(0);
      if (this.buffer.length < length + 4) return;
      const response = Buffer.from(this.buffer.subarray(4, length + 4));
      this.buffer = Buffer.from(this.buffer.subarray(length + 4));
      const waiter = this.queue.shift();
      waiter.resolve(response);
    }
  }

  request(message) {
    return new Promise((resolve, reject) => {
      this.queue.push({ resolve, reject });
      this.socket.write(frame(message));
    });
  }

  end() {
    this.socket.end();
  }
}

function expectFailure(response, code = AGENT_FAILURE) {
  if (response.length !== 1 || response[0] !== code) {
    throw new Error(`expected failure code ${code}, got ${response.toString('hex')}`);
  }
}

async function validPath(client, keys, overrides = {}) {
  const jumpKey = loadPublicBlob(keys, 'jump_host');
  const targetKey = loadPublicBlob(keys, 'target_host');
  const jumpSid = overrides.jumpSid ?? Buffer.alloc(32, 0x11);
  const targetSid = overrides.targetSid ?? Buffer.alloc(32, 0x22);
  const jumpPrivate = loadPrivate(keys, 'jump_host');
  const targetPrivate = loadPrivate(keys, 'target_host');

  expectFailure(await client.request(bindExtension({
    hostKey: jumpKey,
    sessionId: jumpSid,
    signature: signHostSession(jumpPrivate, jumpSid),
    forwarding: true,
  })), AGENT_SUCCESS);
  expectFailure(await client.request(bindExtension({
    hostKey: targetKey,
    sessionId: targetSid,
    signature: signHostSession(targetPrivate, targetSid),
    forwarding: false,
  })), AGENT_SUCCESS);
  return { jumpKey, targetKey, jumpSid, targetSid };
}

async function startTestAgent() {
  const fixture = await makeFixtureAgent();
  const socketPath = path.join(fixture.root, 'agent.sock');
  const server = startAgentServer(fixture.agent, socketPath);
  await new Promise((resolve) => server.server.once('listening', resolve));
  return { ...fixture, socketPath, stop: server.stop };
}

test('returns the configured Ed25519 identity and advertised extension', async () => {
  const testServer = await startTestAgent();
  try {
    const identityResponse = await exchange(
      testServer.socketPath,
      message(SSH2_AGENTC_REQUEST_IDENTITIES),
    );
    const reader = new Reader(identityResponse);
    assert.equal(reader.byte(), SSH2_AGENT_IDENTITIES_ANSWER);
    assert.equal(reader.uint32(), 1);
    const blob = reader.buffer();
    assert.equal(reader.cstring(), 'restricted-demo');
    reader.end();
    assert.deepEqual(blob, testServer.agent.userKey.blob);

    const extResponse = await exchange(testServer.socketPath, message(
      SSH_AGENTC_EXTENSION,
      cstring('query'),
    ));
    const extReader = new Reader(extResponse);
    assert.equal(extReader.byte(), SSH_AGENT_EXTENSION_RESPONSE);
    assert.equal(extReader.cstring(), 'query');
    assert.equal(extReader.cstring(), SESSION_BIND_EXTENSION);
    extReader.end();
  } finally {
    await testServer.stop();
  }
});

test('signs only the complete jump-to-target host-bound authentication path', async () => {
  const testServer = await startTestAgent();
  try {
    const client = await PersistentAgent.connect(testServer.socketPath);
    try {
      await validPath(client, testServer.keys);
      const targetSid = Buffer.alloc(32, 0x22);
      const data = hostboundPayload({
        sessionId: targetSid,
        userKey: testServer.agent.userKey.blob,
        hostKey: loadPublicBlob(testServer.keys, 'target_host'),
      });
      const response = await client.request(signRequest(
        testServer.agent.userKey.blob,
        data,
      ));

      const reader = new Reader(response);
      assert.equal(reader.byte(), SSH2_AGENT_SIGN_RESPONSE);
      const agentSignatureBlob = reader.buffer();
      reader.end();
      const raw = decodeEdSignatureBlob(agentSignatureBlob);
      assert.equal(crypto.verify(null, data, testServer.agent.userKey.keyObject, raw), true);
    } finally {
      client.end();
      await testServer.stop();
    }
  } finally {
    await testServer.stop();
  }
});

test('does not sign arbitrary bytes or ordinary publickey payloads before/after binding', async () => {
  const testServer = await startTestAgent();
  try {
    const client = await PersistentAgent.connect(testServer.socketPath);
    try {
      const key = testServer.agent.userKey.blob;
      expectFailure(await client.request(signRequest(key, Buffer.from('arbitrary'))));
      expectFailure(await client.request(signRequest(key, Buffer.alloc(0))));

      await validPath(client, testServer.keys);
      expectFailure(await client.request(signRequest(key, Buffer.from('arbitrary'))));

      const ordinary = hostboundPayload({
        sessionId: Buffer.alloc(32, 0x22),
        method: 'publickey',
        userKey: key,
        hostKey: loadPublicBlob(testServer.keys, 'target_host'),
      });
      expectFailure(await client.request(signRequest(key, ordinary)));
    } finally {
      client.end();
      await testServer.stop();
    }
  } finally {
    await testServer.stop();
  }
});

test('rejects swapped sessions, hosts, users, keys, service and method', async () => {
  const testServer = await startTestAgent();
  try {
    const client = await PersistentAgent.connect(testServer.socketPath);
    try {
      const { targetKey, jumpKey, jumpSid, targetSid } = await validPath(
        client,
        testServer.keys,
      );
      const base = {
        sessionId: targetSid,
        userKey: testServer.agent.userKey.blob,
        hostKey: targetKey,
      };
      const attempts = [
        { sessionId: jumpSid },
        { sessionId: Buffer.alloc(32, 0x33) },
        { hostKey: jumpKey },
        { hostKey: loadPublicBlob(testServer.keys, 'user') },
        { user: 'root' },
        { user: 'Deploy' },
        { user: 'deploy2' },
        { service: 'other' },
        { method: 'publickey' },
        { algorithm: 'ssh-rsa' },
        { userKey: targetKey },
      ];

      for (const override of attempts) {
        expectFailure(await client.request(signRequest(
          testServer.agent.userKey.blob,
          hostboundPayload({ ...base, ...override }),
        )));
      }

      // A valid request still succeeds after the rejected probes.
      const valid = await client.request(signRequest(
        testServer.agent.userKey.blob,
        hostboundPayload(base),
      ));
      assert.equal(valid[0], SSH2_AGENT_SIGN_RESPONSE);
    } finally {
      client.end();
      await testServer.stop();
    }
  } finally {
    await testServer.stop();
  }
});

test('rejects wrong bind order, bad host signatures, duplicates and post-auth rebinds', async () => {
  const testServer = await startTestAgent();
  try {
    const client = await PersistentAgent.connect(testServer.socketPath);
    try {
      const jumpKey = loadPublicBlob(testServer.keys, 'jump_host');
      const targetKey = loadPublicBlob(testServer.keys, 'target_host');
      const jumpPrivate = loadPrivate(testServer.keys, 'jump_host');
      const targetPrivate = loadPrivate(testServer.keys, 'target_host');
      const sidA = Buffer.alloc(32, 0x11);
      const sidB = Buffer.alloc(32, 0x22);

      // Target first is wrong even if the KEX signature is valid.
      expectFailure(await client.request(bindExtension({
        hostKey: targetKey,
        sessionId: sidB,
        signature: signHostSession(targetPrivate, sidB),
        forwarding: false,
      })), SSH_AGENT_EXTENSION_FAILURE);

      // Forged/foreign signature on the jump session identifier.
      expectFailure(await client.request(bindExtension({
        hostKey: jumpKey,
        sessionId: sidA,
        signature: signHostSession(targetPrivate, sidA),
        forwarding: true,
      })), SSH_AGENT_EXTENSION_FAILURE);

      // Correct first bind.
      expectFailure(await client.request(bindExtension({
        hostKey: jumpKey,
        sessionId: sidA,
        signature: signHostSession(jumpPrivate, sidA),
        forwarding: true,
      })), AGENT_SUCCESS);

      // A second-hop duplicate with an invalid signature is rejected before
      // the duplicate-session state check and cannot record anything.
      const badDuplicateSignature = signHostSession(targetPrivate, sidA);
      badDuplicateSignature[badDuplicateSignature.length - 1] ^= 1;
      expectFailure(await client.request(bindExtension({
        hostKey: targetKey,
        sessionId: sidA,
        signature: badDuplicateSignature,
        forwarding: false,
      })), SSH_AGENT_EXTENSION_FAILURE);

      // Same sid/key on a repeat forwarding bind, and a sid reused against the
      // target key, are both denied.
      expectFailure(await client.request(bindExtension({
        hostKey: jumpKey,
        sessionId: sidA,
        signature: signHostSession(jumpPrivate, sidA),
        forwarding: true,
      })), SSH_AGENT_EXTENSION_FAILURE);
      expectFailure(await client.request(bindExtension({
        hostKey: targetKey,
        sessionId: sidA,
        signature: signHostSession(targetPrivate, sidA),
        forwarding: false,
      })), SSH_AGENT_EXTENSION_FAILURE);

      // Jump cannot be repeated as a non-forwarding hop.
      expectFailure(await client.request(bindExtension({
        hostKey: jumpKey,
        sessionId: Buffer.alloc(32, 0x33),
        signature: signHostSession(jumpPrivate, Buffer.alloc(32, 0x33)),
        forwarding: false,
      })), SSH_AGENT_EXTENSION_FAILURE);

      // Correct second bind is not polluted by those failures.
      expectFailure(await client.request(bindExtension({
        hostKey: targetKey,
        sessionId: sidB,
        signature: signHostSession(targetPrivate, sidB),
        forwarding: false,
      })), AGENT_SUCCESS);

      // Any further bind after the authentication target is rejected.
      expectFailure(await client.request(bindExtension({
        hostKey: targetKey,
        sessionId: Buffer.alloc(32, 0x44),
        signature: signHostSession(targetPrivate, Buffer.alloc(32, 0x44)),
        forwarding: false,
      })), SSH_AGENT_EXTENSION_FAILURE);

      const response = await client.request(signRequest(
        testServer.agent.userKey.blob,
        hostboundPayload({
          sessionId: sidB,
          userKey: testServer.agent.userKey.blob,
          hostKey: targetKey,
        }),
      ));
      assert.equal(response[0], SSH2_AGENT_SIGN_RESPONSE);
    } finally {
      client.end();
      await testServer.stop();
    }
  } finally {
    await testServer.stop();
  }
});

test('bindings are isolated to each socket and destroyed on close', async () => {
  const testServer = await startTestAgent();
  try {
    const jumpKey = loadPublicBlob(testServer.keys, 'jump_host');
    const targetKey = loadPublicBlob(testServer.keys, 'target_host');
    const sidA = Buffer.alloc(32, 0x11);
    const sidB = Buffer.alloc(32, 0x22);

    const first = await connectPair(testServer.socketPath);
    writeRequest(first, bindExtension({
      hostKey: jumpKey,
      sessionId: sidA,
      signature: signHostSession(loadPrivate(testServer.keys, 'jump_host'), sidA),
      forwarding: true,
    }));
    assert.equal((await nextResponse(first))[0], AGENT_SUCCESS);
    first.end();

    // A second connection must not inherit the first socket's forwarding hop.
    const second = await connectPair(testServer.socketPath);
    writeRequest(second, bindExtension({
      hostKey: targetKey,
      sessionId: sidB,
      signature: signHostSession(loadPrivate(testServer.keys, 'target_host'), sidB),
      forwarding: false,
    }));
    assert.equal((await nextResponse(second))[0], SSH_AGENT_EXTENSION_FAILURE);

    // Same sid on a fresh socket is allowed because state was destroyed.
    writeRequest(second, bindExtension({
      hostKey: jumpKey,
      sessionId: sidA,
      signature: signHostSession(loadPrivate(testServer.keys, 'jump_host'), sidA),
      forwarding: true,
    }));
    assert.equal((await nextResponse(second))[0], AGENT_SUCCESS);
    writeRequest(second, bindExtension({
      hostKey: targetKey,
      sessionId: sidB,
      signature: signHostSession(loadPrivate(testServer.keys, 'target_host'), sidB),
      forwarding: false,
    }));
    assert.equal((await nextResponse(second))[0], AGENT_SUCCESS);
    writeRequest(second, signRequest(
      testServer.agent.userKey.blob,
      hostboundPayload({
        sessionId: sidB,
        userKey: testServer.agent.userKey.blob,
        hostKey: targetKey,
      }),
    ));
    assert.equal((await nextResponse(second))[0], SSH2_AGENT_SIGN_RESPONSE);
    second.end();
  } finally {
    await testServer.stop();
  }
});

test('refuses add/remove/lock/smartcard/certificate messages and malformed packet contents', async () => {
  const testServer = await startTestAgent();
  try {
    for (const type of [17, 18, 19, 20, 21, 22, 23, 25, 26, 30, 100]) {
      expectFailure(await exchange(testServer.socketPath, message(type)));
    }

    const unknownExtension = await exchange(testServer.socketPath, message(
      SSH_AGENTC_EXTENSION,
      cstring('restrict-destination-v00@openssh.com'),
    ));
    assert.equal(unknownExtension[0], SSH_AGENT_EXTENSION_FAILURE);

    const validBind = bindExtension({
      hostKey: loadPublicBlob(testServer.keys, 'jump_host'),
      sessionId: Buffer.alloc(32, 0x11),
      signature: signHostSession(loadPrivate(testServer.keys, 'jump_host'), Buffer.alloc(32, 0x11)),
      forwarding: true,
    });
    expectFailure(await exchange(
      testServer.socketPath,
      Buffer.concat([validBind, Buffer.from([0xff])]),
    ));

    const overlong = Buffer.alloc(9);
    overlong.writeUInt32BE(MAX_MESSAGE + 1, 0);
    assert.deepEqual(await exchangeRaw(testServer.socketPath, overlong), Buffer.alloc(0));
  } finally {
    await testServer.stop();
  }
});
