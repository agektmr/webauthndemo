'use strict';

const cbor = require('cbor');
const Algorithm = require('./Algorithm');

const CRV_LABEL = -1;
const X_LABEL = -2;
const Y_LABEL = -3;
const N_LABEL = -1;
const E_LABEL = -2;
const KTY_LABEL = 1;
const ALG_LABEL = 3;

class CredentialPublicKey {
  static decode(buffer) {
    const dataItem = cbor.decodeFirstSync(buffer);

    // If there are 4 keys in the map, the key should be RSA. If there are 5, then it is ECC.
    if (dataItem.size === 4) {
      // rsaKey = new RsaKey();
      rsaKey = {};

      for (let d of dataItem.keys()) {
        switch (d) {
          case N_LABEL:
            rsaKey.n = dataItem[d];
            break;
          case E_LABEL:
            rsaKey.e = dataItem[d];
            break;
          case KTY_LABEL:
            rsaKey.kty = dataItem[d];
            break;
          case ALG_LABEL:
            rsaKey.alg = Algorithm.decode(dataItem[d]);
            if (!Algorithm.isRsaAlgorithm(rsaKey.alg))
              throw new InvalidParameterException("Unsupported RSA algorithm");
            break;
        }
      }
      return rsaKey;

    } else if (dataItem.size == 5) {
      // const eccKey = new EccKey();
      const eccKey = {};

      for (let d of dataItem.keys()) {
        switch (d) {
          case CRV_LABEL:
            eccKey.crv = dataItem[d];
            break;
          case X_LABEL:
            eccKey.x = dataItem[d];
            break;
          case Y_LABEL:
            eccKey.y = dataItem[d];
            break;
          case KTY_LABEL:
            eccKey.kty = dataItem[d];
            break;
          case ALG_LABEL:
            eccKey.alg = Algorithm.decode(dataItem[d]);
            if (!Algorithm.isEccAlgorithm(eccKey.alg))
              throw new InvalidParameterException("Unsupported ECC algorithm");
            break;
        }
      }
      return eccKey;
    }

    throw new InvalidParameterException("Unsupported COSE public key sent");
  }
}

class AttestationData {
  constructor() {
    this.aaguid = new Buffer(16);
    this.credentialId = null;
    this.publicKey = null;
  }
  static decode(data) {
    const result = new AttestationData();
    let index = 0;
    if (data.length < 18) throw "Invalid input";
    AuthenticatorData.arraycopy(data, 0, result.aaguid, 0, 16);
    index += 16;

    let length = (data[index++] << 8) & 0xFF;
    length += data[index++] & 0xFF;

    result.credentialId = new Buffer(length);
    AuthenticatorData.arraycopy(data, index, result.credentialId, 0, length);
    index += length;

    const buffer = new Buffer(data.length - index);
    AuthenticatorData.arraycopy(data, index, buffer, 0, data.length - index);
    result.publicKey = CredentialPublicKey.decode(buffer);

    return result;
  }
  static arraycopy(src, srcs, dst, dsts, length) {
    for (let i = 0; i < length; i++) {
      dst[dsts+i] = src[srcs+i];
    }
  }
}

class AuthenticatorData {
  constructor(rpIdHash, flags, signCount, attData) {
    this.rpIdHash = rpIdHash;
    this.flags = flags;
    this.signCount = signCount;
    this.attData = null;
  }
  static decode(authData) {
    if (authData.length < 37) throw "Invalid input";

    let index = 0;
    const rpIdHash = new Buffer(32);
    AuthenticatorData.arraycopy(authData, 0, rpIdHash, 0, 32);
    index += 32;
    const flags = authData[index++];
    const signCount =
        // Ints.fromBytes(authData[index++], authData[index++], authData[index++], authData[index++]);
        AuthenticatorData.intFromBytes(authData[index++], authData[index++], authData[index++], authData[index++]);
    let attData = null;

    // Bit 6 determines whether attestation data was included
    if ((flags & 1 << 6) != 0) {
      const remainder = new Buffer(authData.length - index);
      AuthenticatorData.arraycopy(authData, index, remainder, 0, authData.length - index);
      attData = AttestationData.decode(remainder);
    }

    return new AuthenticatorData(rpIdHash, flags, signCount, attData);
  }
  static intFromBytes(a, b, c, d) {
    // TODO: This sure needs rework
    let result = 0;
    result += a << 32;
    result += b << 16;
    result += c << 8;
    result += d;
    return result;
  }
  static arraycopy(src, srcs, dst, dsts, length) {
    for (let i = 0; i < length; i++) {
      dst[dsts+i] = src[srcs+i];
    }
  }
}

class AttestationObject {
  constructor(authData = null, fmt = null, attStmt = null) {
    this.authData = authData;
    this.fmt = fmt;
    this.attStmt = attStmt;
  }
  static decode(attestationObject) {
    const result = new AttestationObject();
    const dataItem = cbor.decodeFirstSync(attestationObject);

    let attStmt = null;
    for (let key of Object.keys(dataItem)) {
      switch (key) {
        case 'fmt':
          result.fmt = dataItem[key];
          break;
        case 'authData':
          let authData = dataItem[key];
          result.authData = AuthenticatorData.decode(authData);
          break;
        case 'attStmt':
          attStmt = dataItem[key];
          break;
      }
    }

    if (attStmt != null) {
      result.attStmt = AttestationStatement.decode(result.fmt, attStmt);
    }

    return result;
  }
}

// class AuthenticatorAttestationResponse extends AuthenticatorResponse {
class AuthenticatorAttestationResponse {
  constructor(data) {
    const attestationObject = new Buffer(data.attestationObject, 'base64');
    this.decodedObject = AttestationObject.decode(attestationObject);
    this.clientDataBytes = new Buffer(data.clientDataJSON, 'base64');
  }
  encode() {
    return {
      clientDataJSON: this.clientDataBytes.base64Slice(),
      attestationObject: this.decodedObject.base64Slice()
    }
  }
}

// module.exports = {
//   CredentialPublicKey: CredentialPublicKey,
//   AuthenticatorAttestationResponse: AuthenticatorAttestationResponse
// }
module.exports = AuthenticatorAttestationResponse;