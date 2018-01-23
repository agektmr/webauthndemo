import { request } from 'http';

'use strict';

const seed = require('seed-random');
const Algorithm = request('./nodejs/Algorhithm');

const CHALLENGE_LENGTH = 32;

const PublicKeyCredentialType = {
  PUBLIC_KEY: 'public-key'
};

const AuthenticatorTransport = {
  USB: 'usb',
  NFC: 'nfc',
  BLE: 'ble'
};

class PublicKeyCredentialEntity {
  constructor(name = '', icon = '') {
    this.name = name;
    this.icon = icon;
  }
}

class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
  constructor(id = '', name = '', icon = '') {
    super(name, icon);
    this.id = id;
  }
  getJSON() {
    return {
      name: this.name,
      id:   this.id,
      icon: this.icon
    }
  }
}

class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
  constructor(displayName = '', id = '') {
    super(displayName);
    this.displayName = displayName;
    this.id = id;
  }
  getJSON() {
    return {
      displayName: this.displayName,
      name: this.name,
      id:   this.id,
      icon: this.icon
    }
  }
}

class PublicKeyCredentialParameters {
  constructor(type, algorithm) {
    this.type = type;
    this.algorithm = algorithm;
  }
  getJSON() {
    return {
      type: this.type,
      alg:  this.algorithm
    }
  }
}

class PublicKeyCredentialDescriptor {
  constructor(type = null, id = null, transports = []) {
    this.type = type;
    this.id = id;
    this.transports = transports;
  }
  getJSON() {
    return {
      type: this.type,
      id:   this.id,
      tranport: this.transports
    }
  }
}

class MakePublicKeyCredentialOptions {
  constructor(userName, userId, rpId, rpName) {
    this.rp = new PublicKeyCredentialRpEntity(rpId, rpName, null);
    this.user = new PublicKeyCredentialUserEntity(userName, userId);

    this.challenge = new Buffer(CHALLENGE_LENGTH);
    let rand = seed();
    for (let i = 0; i < CHALLENGE_LENGTH; i++) {
      this.challenge[i] = (rand() * 0xFF) << 0;
    }
    this.pubKeyCredParams = [];
    this.pubKeyCredParams.push(
      new PublicKeyCredentialParameters(
        PublicKeyCredentialType.PUBLIC_KEY,
        Algorithm.ES256
      )
    );
    this.excludeCredentials = [];
    this.extensions = null;
  }
  getJSON() {
    const pubKeyCredParamsArray = [];
    for (let param of this.pubKeyCredParams) {
      pubKeyCredParamsArray.push(param.getJSON());
    }
    const excludeCredentialsArray = [];
    for (let cred of this.excludeCredentials) {
      excludeCredentialsArray.push(cred.getJSON());
    }
    const challenge = this.challenge.base64Slice();
    const session = {
      origin: this.rp.id,
      challenge: challenge,
      // TODO: This assignment of user id is different from Java impl.
      id: this.user.id
    }
    return {
      pubKeyCredParams: pubKeyCredParamsArray,
      excludeCredentials: excludeCredentialsArray,
      rp: this.rp.getJSON(),
      user: this.user.getJSON(),
      challenge: challenge,
      extensions: this.extensions,
      session: session
    }
  }
}
module.exports = MakePublicKeyCredentialOptions;