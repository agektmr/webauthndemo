'use strict';

const aar = require('../../main/nodejs/AuthenticatorAttestationResponse');
const CredentialPublicKey = aar.CredentialPublicKey;
const Algorithm = require('../../main/nodejs/Algorithm');

// TODO: This is not functional as EccKey is not defined

const eccKey = {};
eccKey.alg = Algorithm.decode("-7");
eccKey.x = new Buffer([0, 1, 2, 3]);
eccKey.y = new Buffer([0, 2, 4, 6]);
const rsaKey = {};
rsaKey.alg = Algorithm.decode("PS512");
rsaKey.e = new Buffer([0, 1, 2, 3]);
rsaKey.n = new Buffer([0, 2, 4, 6]);

const ecc = CredentialPublicKey.decode(eccKey.encode());
const rsa = CredentialPublicKey.decode(rsaKey.encode());
assertTrue(ecc instanceof EccKey);
assertEquals(ecc, eccKey);
assertTrue(rsa instanceof RsaKey);
assertEquals(rsa, rsaKey);
