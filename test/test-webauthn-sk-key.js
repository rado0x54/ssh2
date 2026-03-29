'use strict';

const assert = require('assert');
const { parseKey } = require('../lib/protocol/keyParser.js');

// Build a binary wire-format WebAuthn SK ECDSA public key:
//   string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
//   string  "nistp256"
//   string  ecPoint (0x04 || 32-byte X || 32-byte Y)
//   string  application
function buildWireKey(ecPoint, application) {
  const algo = Buffer.from('webauthn-sk-ecdsa-sha2-nistp256@openssh.com');
  const curve = Buffer.from('nistp256');
  const app = Buffer.from(application);

  const buf = Buffer.allocUnsafe(
    4 + algo.length + 4 + curve.length + 4 + ecPoint.length + 4 + app.length
  );
  let offset = 0;

  buf.writeUInt32BE(algo.length, offset); offset += 4;
  algo.copy(buf, offset); offset += algo.length;

  buf.writeUInt32BE(curve.length, offset); offset += 4;
  curve.copy(buf, offset); offset += curve.length;

  buf.writeUInt32BE(ecPoint.length, offset); offset += 4;
  ecPoint.copy(buf, offset); offset += ecPoint.length;

  buf.writeUInt32BE(app.length, offset); offset += 4;
  app.copy(buf, offset);

  return buf;
}

// Generate a fake uncompressed EC point (0x04 + 64 random bytes)
const ecPoint = Buffer.alloc(65);
ecPoint[0] = 0x04;
for (let i = 1; i < 65; i++)
  ecPoint[i] = i;

const application = 'localhost';
const wireKey = buildWireKey(ecPoint, application);

// Test 1: parseKey succeeds on valid wire-format key
{
  const key = parseKey(wireKey);
  assert(!(key instanceof Error), `parseKey failed: ${key.message || key}`);
  assert.strictEqual(key.type, 'webauthn-sk-ecdsa-sha2-nistp256@openssh.com');
  assert.strictEqual(key.comment, '');
  assert.strictEqual(key.isPrivateKey(), false);
  assert.strictEqual(key.getPublicPEM(), null);
  assert.strictEqual(key.getPrivatePEM(), null);
  console.log('[PASS] parseKey returns valid WebAuthnSKECDSAKey');
}

// Test 2: getPublicSSH() round-trips correctly
{
  const key = parseKey(wireKey);
  const pubSSH = key.getPublicSSH();
  assert(Buffer.isBuffer(pubSSH));
  assert(pubSSH.equals(wireKey), 'getPublicSSH() does not match input wire key');
  console.log('[PASS] getPublicSSH() round-trips to original wire format');
}

// Test 3: equals() works
{
  const key1 = parseKey(wireKey);
  const key2 = parseKey(wireKey);
  assert.strictEqual(key1.equals(key2), true);
  console.log('[PASS] equals() returns true for identical keys');
}

// Test 4: equals() rejects different keys
{
  const ecPoint2 = Buffer.alloc(65);
  ecPoint2[0] = 0x04;
  for (let i = 1; i < 65; i++)
    ecPoint2[i] = 65 - i;

  const wireKey2 = buildWireKey(ecPoint2, application);
  const key1 = parseKey(wireKey);
  const key2 = parseKey(wireKey2);
  assert.strictEqual(key1.equals(key2), false);
  console.log('[PASS] equals() returns false for different keys');
}

// Test 5: equals() rejects different application
{
  const wireKey2 = buildWireKey(ecPoint, 'example.com');
  const key1 = parseKey(wireKey);
  const key2 = parseKey(wireKey2);
  assert.strictEqual(key1.equals(key2), false);
  console.log('[PASS] equals() returns false for different application');
}

// Test 6: sign/verify return errors (must use agent)
{
  const key = parseKey(wireKey);
  const signResult = key.sign(Buffer.from('test'));
  assert(signResult instanceof Error);
  const verifyResult = key.verify(Buffer.from('test'), Buffer.from('sig'));
  assert(verifyResult instanceof Error);
  console.log('[PASS] sign() and verify() return errors as expected');
}

// Test 7: malformed key - wrong curve
{
  const algo = Buffer.from('webauthn-sk-ecdsa-sha2-nistp256@openssh.com');
  const curve = Buffer.from('nistp384');
  const app = Buffer.from('localhost');
  const buf = Buffer.allocUnsafe(
    4 + algo.length + 4 + curve.length + 4 + ecPoint.length + 4 + app.length
  );
  let offset = 0;
  buf.writeUInt32BE(algo.length, offset); offset += 4;
  algo.copy(buf, offset); offset += algo.length;
  buf.writeUInt32BE(curve.length, offset); offset += 4;
  curve.copy(buf, offset); offset += curve.length;
  buf.writeUInt32BE(ecPoint.length, offset); offset += 4;
  ecPoint.copy(buf, offset); offset += ecPoint.length;
  buf.writeUInt32BE(app.length, offset); offset += 4;
  app.copy(buf, offset);
  const key = parseKey(buf);
  assert(key instanceof Error, 'Expected error for wrong curve');
  console.log('[PASS] Rejects key with wrong curve');
}

// Test 8: malformed key - wrong EC point length
{
  const shortPoint = Buffer.alloc(33);
  shortPoint[0] = 0x04;
  const wire = buildWireKey(shortPoint, 'localhost');
  const key = parseKey(wire);
  assert(key instanceof Error, 'Expected error for wrong EC point length');
  console.log('[PASS] Rejects key with wrong EC point length');
}

// Test 9: malformed key - wrong EC point prefix
{
  const badPoint = Buffer.alloc(65);
  badPoint[0] = 0x02; // compressed, not uncompressed
  const wire = buildWireKey(badPoint, 'localhost');
  const key = parseKey(wire);
  assert(key instanceof Error, 'Expected error for wrong EC point prefix');
  console.log('[PASS] Rejects key with wrong EC point prefix');
}

// Test 10: existing key types still parse fine (regression)
{
  const { readFileSync } = require('fs');
  const BASE_PATH = `${__dirname}/fixtures/keyParser`;
  const rsaPub = readFileSync(`${BASE_PATH}/openssh_new_rsa.pub`);
  const key = parseKey(rsaPub);
  assert(!(key instanceof Error), `RSA key parsing broke: ${key.message || key}`);
  assert.strictEqual(key.type, 'ssh-rsa');
  console.log('[PASS] Existing RSA key parsing still works (regression check)');
}

console.log('\nAll WebAuthn SK ECDSA tests passed.');
