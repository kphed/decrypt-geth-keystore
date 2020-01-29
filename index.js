// USES LOGIC FROM VARIOUS PACKAGES (WAS FOR SELF-EDUCATION PURPOSES)
// SEE SOURCES BELOW

// Credit to Greg Jeanmart on StackOverflow for pointing me towards the answer
// https://ethereum.stackexchange.com/a/47036

const crypto = require('crypto');
const fs = require('fs');

// https://github.com/ricmoo/scrypt-js
const { scrypt } = require('scrypt-js');

// Logic from ethereumjs-util - please see below
// https://github.com/ethereumjs/ethereumjs-util/blob/master/src/hash.ts#L13
const createKeccakHash = require('keccak');
const keccak = (a, bits) => {
  var re = /[0-9A-Fa-f]{6}/g;

  // Replaced using ethutil method for checking if `a` is hex string
  if (typeof a === 'string' && !re.test(a)) {
    a = Buffer.from(a, 'utf8');
  }

  if (!bits) bits = 256;

  return createKeccakHash(`keccak${bits}`)
    .update(a)
    .digest();
};

// https://github.com/ethereumjs/ethereumjs-wallet/blob/master/src/index.ts#L565
const runCipherBuffer = (cipher, data) => {
  return Buffer.concat([cipher.update(data), cipher.final()]);
};

// https://github.com/ethereumjs/ethereumjs-wallet/blob/master/src/index.ts#L340
const extractPrivateKey = async (input, password) => {
  const json = JSON.parse(input);

  if (json.version !== 3) {
    throw new Error('Not a V3 wallet');
  }

  let derivedKey, kdfparams;

  if (json.crypto.kdf === 'scrypt') {
    kdfparams = json.crypto.kdfparams;

    // FIXME: support progress reporting callback
    derivedKey = await scrypt(
      Buffer.from(password),
      Buffer.from(kdfparams.salt, 'hex'),
      kdfparams.n,
      kdfparams.r,
      kdfparams.p,
      kdfparams.dklen,
    );
  }

  const ciphertext = Buffer.from(json.crypto.ciphertext, 'hex');
  const mac = keccak(Buffer.concat([derivedKey.slice(16, 32), ciphertext]));

  if (mac.toString('hex') !== json.crypto.mac) {
    throw new Error('Key derivation failed - possibly wrong passphrase');
  }

  const decipher = crypto.createDecipheriv(
    json.crypto.cipher,
    derivedKey.slice(0, 16),
    Buffer.from(json.crypto.cipherparams.iv, 'hex'),
  );

  const results = runCipherBuffer(decipher, ciphertext).toString('hex');

  // Writes private key to file
  return fs.writeFileSync('./keyfile', results);
};

const keystore = fs.readFileSync(process.argv[2]).toString();
const password = fs.readFileSync(process.argv[3]).toString().trim();

extractPrivateKey(keystore, password);
