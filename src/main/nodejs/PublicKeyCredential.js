'use strict';

class PublicKeyCredential {
  constructor(id, type, rawId, response) {
    this.id = id;
    this.type = type;
    this.rawId = rawId;
    this.response = response;
  }
  getAttestationType() {
    try {
      const attStmt = this.response.decodedObject.getAttestationStatement();
      // AttestationStatement attStmt = attRsp.decodedObject.getAttestationStatement();
      if (attStmt instanceof AndroidSafetyNetAttestationStatement) {
        return AttestationStatementEnum.ANDROIDSAFETYNET;
      } else if (attStmt instanceof FidoU2fAttestationStatement) {
        return AttestationStatementEnum.FIDOU2F;
      } else if (attStmt instanceof PackedAttestationStatement) {
        return AttestationStatementEnum.PACKED;
      }
    } catch (ClassCastException e) {
      return null;
    }
    return null;
  }
}
module.exports = PublicKeyCredential;