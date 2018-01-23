'use strict';

const ES256 = -7;
const ES384 = -35;
const ES512 = -36;
const PS256 = -37;
const PS384 = -38;
const PS512 = -39;
const RS256 = -40;
const RS384 = -41;
const RS512 = -42;

class Algorithm {
  static get ES256() { return ES256; }
  static get ES384() { return ES384; }
  static get ES512() { return ES512; }
  static get PS256() { return PS256; }
  static get PS384() { return PS384; }
  static get PS512() { return PS512; }
  static get RS256() { return RS256; }
  static get RS384() { return RS384; }
  static get RS512() { return RS512; }

  static isEccAlgorithm(alg) {
    return alg === ES256 ||
           alg === ES384 ||
           alg === ES512;
  }
  static isRsaAlgorithm(alg) {
    return alg === RS256 ||
           alg === RS384 ||
           alg === RS512 ||
           alg === PS256 ||
           alg === PS384 ||
           alg === PS512;
  }
  static encode(str) {
    switch(str) {
      case 'ES256':
        return ES256;
      case 'ES384':
        return ES384;
      case 'ES512':
        return ES512;
      case 'PS256':
        return PS256;
      case 'PS384':
        return PS384;
      case 'PS512':
        return PS512;
      case 'RS256':
        return RS256;
      case 'RS384':
        return RS384;
      case 'RS512':
        return RS512;
      default:
        return undefined;
    }
  }
  static decode(num) {
    switch(num) {
      case ES256:
        return 'ES256';
      case ES384:
        return 'ES384';
      case ES512:
        return 'ES512';
      case PS256:
        return 'PS256';
      case PS384:
        return 'PS384';
      case PS512:
        return 'PS512';
      case RS256:
        return 'RS256';
      case RS384:
        return 'RS384';
      case RS512:
        return 'RS512';
      default:
        return undefined;
    }
  }
}

module.exports = Algorithm;
