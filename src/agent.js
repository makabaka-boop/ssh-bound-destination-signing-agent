import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import crypto from 'node:crypto';
import {
  AGENT_SUCCESS,
  MAX_MESSAGE,
  ParseError,
  Reader,
  SESSION_BIND_EXTENSION,
  SSH2_AGENTC_REQUEST_IDENTITIES,
  SSH2_AGENTC_SIGN_REQUEST,
  SSH2_AGENT_IDENTITIES_ANSWER,
  SSH2_AGENT_SIGN_RESPONSE,
  SSH_AGENTC_EXTENSION,
  SSH_AGENT_EXTENSION_FAILURE,
  SSH_AGENT_EXTENSION_RESPONSE,
  cstring,
  encodeEdSignature,
  failure,
  frame,
  message,
  string,
} from './protocol.js';
import { AuthorizationError, RestrictedAgent } from './authorization.js';

function logDenial(reason, extra = {}) {
  const details = Object.entries(extra)
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(' ');
  console.warn(`authorization denied: ${reason}${details ? ` ${details}` : ''}`);
}

function deny(reason, response = failure(), extra) {
  logDenial(reason, extra);
  return response;
}

function queryExtensionsResponse() {
  return message(
    SSH_AGENT_EXTENSION_RESPONSE,
    Buffer.concat([
      cstring('query'),
      cstring(SESSION_BIND_EXTENSION),
    ]),
  );
}

function buildIdentitiesResponse(agent) {
  const identities = agent.identities();
  const count = Buffer.alloc(4);
  count.writeUInt32BE(identities.length, 0);
  const entries = Buffer.concat(identities
    .map(({ blob, comment }) => Buffer.concat([string(blob), cstring(comment)])));
  return message(SSH2_AGENT_IDENTITIES_ANSWER, Buffer.concat([count, entries]));
}

function handleRequest(agent, binding, request) {
  if (request.length === 0) return failure();

  const type = request[0];
  const reader = new Reader(request.subarray(1));

  try {
    if (type === SSH2_AGENTC_REQUEST_IDENTITIES) {
      reader.end();
      return buildIdentitiesResponse(agent);
    }

    if (type === SSH2_AGENTC_SIGN_REQUEST) {
      const keyBlob = reader.buffer();
      const payload = reader.buffer();
      const flags = reader.uint32();
      reader.end();

      try {
        const authorizedPayload = binding.authorizeSignature({
          keyBlob,
          payload,
          flags,
        });
        const rawSignature = crypto.sign(null, authorizedPayload, agent.userKey.keyObject);
        return message(SSH2_AGENT_SIGN_RESPONSE, string(encodeEdSignature(rawSignature)));
      } catch (err) {
        if (err instanceof AuthorizationError) return deny(err.message);
        throw err;
      }
    }

    if (type === SSH_AGENTC_EXTENSION) {
      const name = reader.cstring();

      if (name === 'query') {
        reader.end();
        return queryExtensionsResponse();
      }

      if (name === SESSION_BIND_EXTENSION) {
        const hostKeyBlob = reader.buffer();
        const sessionId = reader.buffer();
        const signatureBlob = reader.buffer();
        const forwarding = reader.boolean();
        reader.end();
        try {
          binding.bind({ hostKeyBlob, sessionId, signatureBlob, forwarding });
          return message(AGENT_SUCCESS);
        } catch (err) {
          if (err instanceof AuthorizationError || err instanceof ParseError) {
            return deny(err.message, message(SSH_AGENT_EXTENSION_FAILURE));
          }
          throw err;
        }
      }

      reader.end();
      return deny(`unsupported extension: ${name}`, message(SSH_AGENT_EXTENSION_FAILURE));
    }

    return deny(`unsupported agent message type ${type}`);
  } catch (err) {
    if (err instanceof ParseError) return deny(`malformed request: ${err.message}`);
    throw err;
  }
}

export function startAgentServer(agent, socketPath) {
  const socketDir = path.dirname(socketPath);
  fs.mkdirSync(socketDir, { recursive: true, mode: 0o700 });
  try {
    if (fs.statSync(socketPath).isSocket()) fs.unlinkSync(socketPath);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }

  const server = net.createServer((socket) => {
    // Each Unix-socket connection gets its own two-hop state. Closing the
    // socket drops the only reference and destroys the binding.
    const binding = agent.createBinding();
    let pending = Buffer.alloc(0);
    let destroyed = false;

    const destroySocket = () => {
      if (destroyed) return;
      destroyed = true;
      socket.destroy();
    };

    socket.on('data', (chunk) => {
      pending = Buffer.concat([pending, chunk]);

      while (pending.length >= 4) {
        const length = pending.readUInt32BE(0);
        if (length < 1 || length > MAX_MESSAGE) {
          logDenial(`invalid agent frame length ${length}`);
          pending = Buffer.alloc(0);
          destroySocket();
          return;
        }
        const frameLength = length + 4;
        if (pending.length < frameLength) return;

        const request = Buffer.from(pending.subarray(4, frameLength));
        pending = Buffer.from(pending.subarray(frameLength));

        let response;
        try {
          response = handleRequest(agent, binding, request);
        } catch (err) {
          console.error('internal agent error:', err);
          response = failure();
        }
        if (!socket.destroyed) socket.write(frame(response));
      }
    });

    socket.on('error', (err) => {
      if (err.code !== 'ECONNRESET' && err.code !== 'EPIPE') {
        console.warn('agent socket error:', err.message);
      }
    });

    socket.on('close', () => {
      pending = Buffer.alloc(0);
      socket.removeAllListeners();
    });
  });

  server.on('error', (err) => {
    console.error('agent server error:', err);
    throw err;
  });

  server.listen(socketPath, () => {
    fs.chmodSync(socketPath, 0o600);
    console.log(`restricted SSH agent listening on ${socketPath}`);
  });

  const stop = async () => {
    await new Promise((resolve) => server.close(resolve));
    try {
      fs.unlinkSync(socketPath);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
  };

  return { server, stop };
}

export function createConfiguredAgent(env = process.env) {
  return new RestrictedAgent({
    userPrivateKeyPath: env.USER_KEY_PATH || '/app/keys/user_ed25519.pem',
    jumpPublicKeyPath: env.JUMP_HOST_PUBLIC_KEY || '/app/keys/jump_host_ed25519.pub',
    targetPublicKeyPath: env.TARGET_HOST_PUBLIC_KEY || '/app/keys/target_host_ed25519.pub',
    targetUser: env.TARGET_USER || 'deploy',
  });
}

function main() {
  const socketPath = process.env.SOCKET_PATH || '/run/restricted-ssh-agent/agent.sock';
  const agent = createConfiguredAgent();
  const server = startAgentServer(agent, socketPath);

  const shutdown = async () => {
    try {
      await server.stop();
    } finally {
      process.exit(0);
    }
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

// Identify the main entry point without importing a module-only test runner.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
