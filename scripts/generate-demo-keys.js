import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const ED25519 = 'ssh-ed25519';

export function sshEd25519PublicLine(keyObject, comment) {
  const { x } = keyObject.export({ format: 'jwk' });
  const raw = Buffer.from(x, 'base64url');
  const algorithm = Buffer.from(ED25519, 'ascii');
  const wire = Buffer.concat([
    Buffer.from([0, 0, 0, algorithm.length]),
    algorithm,
    Buffer.from([0, 0, 0, raw.length]),
    raw,
  ]);
  return `${ED25519} ${wire.toString('base64')} ${comment}\n`;
}

async function writeKeyPair(directory, name, comment) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  const privatePath = path.join(directory, `${name}_ed25519.pem`);
  const publicPath = path.join(directory, `${name}_ed25519.pub`);

  fs.writeFileSync(privatePath, privatePem, { mode: 0o600 });
  fs.writeFileSync(publicPath, sshEd25519PublicLine(publicKey, comment), { mode: 0o644 });
}

export async function generateDemoKeys(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  await Promise.all([
    writeKeyPair(directory, 'user', 'restricted-demo'),
    writeKeyPair(directory, 'jump_host', 'fixed-jump-host'),
    writeKeyPair(directory, 'target_host', 'fixed-target-host'),
  ]);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const directory = process.argv[2] || process.env.KEYS_DIR || '/app/keys';
  await generateDemoKeys(directory);
  console.log(`Generated demo Ed25519 keys in ${directory}`);
}
