import { read } from 'fs';
import { request } from 'http';

'use strict';
const express = require('express');
const path = require('path');
const fs = require('fs');
const cbor = require('cbor');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const MakePublicKeyCredentialOptions = require('./nodejs/MakePublicKeyCredentialOptions');
const PublicKeyCredential = require('./nodejs/PublicKeyCredential');
const AuthenticatorAttestationResponse = require('./nodejs/AuthenticatorAttestationResponse');

const app = express();
app.set('trust proxy');
app.set('views', path.join(__dirname, 'nodejs', 'template'));
app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(cookieParser());
app.use((req, res, next) => {
  if (req.hostname !== 'localhost' && !req.secure) {
    return res.redirect(`https://${req.headers.host}${req.url}`, 301);
  }
  next();
});
app.use(express.static(path.join(__dirname, 'webapp'), {
  setHeaders: res => {
    res.set('Strict-Transport-Security', 'max-age=31536000');
  }
}));
app.use(session({
  secret: 'abc',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 365 * 24 * 60 * 60 * 1000
  }
}));

const sessionCheck = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.status(401).send('Authorization required.');
  }
};

app.post('/RegisteredKeys', sessionCheck, (req, res) => {

});
app.get('/BeginMakeCredential', sessionCheck, (req, res) => {
  const user = req.session.user;
  const rpId = req.hostname;
  const rpName = 'webauthndemo';
  const options = new MakePublicKeyCredentialOptions(
    user.name, user.id, rpId, rpName
  );
  // if (req.body.advanced) {
  //   const advancedOptions = req.body.advancedOptions;
  // }
  res.set('Content-Type', 'application/json');
  res.send(options.getJSON());
});
app.post('/FinishMakeCredential', sessionCheck, (req, res) => {
  // Example payload
  /**
    data: {
      "id":"SPYfP_Oon0svkKVSZDj7iYWme3EWaLpJUbY-4L05fvgegpGPL5DoDpLUeQe0unvw0SFDO4PlFge7b8Jv5tezjw",
      "type":"public-key",
      "rawId":"SPYfP/Oon0svkKVSZDj7iYWme3EWaLpJUbY+4L05fvgegpGPL5DoDpLUeQe0unvw0SFDO4PlFge7b8Jv5tezjw==",
      "response":{
        "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJBNkxuekZucXZhR3d1VUplbFpzcUwzYWpULWZlNEVILV90cnVIZm8zZ3IwIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwidG9rZW5CaW5kaW5nIjoidW51c2VkIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
        "attestationObject":"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAKDkMFyD/MOOJuvtdTKMpMU1gCDmVPlnI9flLA1bkHCKAiEAnhJwKzWWa4Iv6iD47uMvEufqxVfX2IrLS+EGiPRcTdxjeDVjgVkBKjCCASYwgcygAwIBAgIBATAKBggqhkjOPQQDAjAOMQwwCgYDVQQDEwNVMkYwIhgPMjAwMDAxMDEwMDAwMDBaGA8yMDk5MTIzMTIzNTk1OVowDjEMMAoGA1UEAxMDVTJGMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE//oBOvQLbhvBfmnOt7vGVIzTrjLNj3RF6Qe51YaMK6MJ09sA62TKEa6eeeDVZ2S3yiOVaSV0TEZkNW+Q6Fi0k6MXMBUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwCgYIKoZIzj0EAwIDSQAwRgIhAJJNwsg1oeUgUrGI5mMJTBFZC3kSnDL68NW5iBvhMIG0AiEA5yZjTOnJGaBqQZ+LutnLeKZCiefc9GNzzZ09Y5oupspoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEBI9h8/86ifSy+QpVJkOPuJhaZ7cRZouklRtj7gvTl++B6CkY8vkOgOktR5B7S6e/DRIUM7g+UWB7tvwm/m17OPpQECAyYgASFYIP/6ATr0C24bwX5pzre7xlSM064yzY90RekHudWGjCujIlggCdPbAOtkyhGunnng1Wdkt8ojlWkldExGZDVvkOhYtJM="
      }
    },
    session: 6306798696923136
   */
  const currentUser = req.esssion.user;
  const data = req.body.data;
  const session = req.body.session;
  const attestation = new AuthenticatorAttestationResponse(data.reponse);

  const rawId = new Buffer(data.id, 'base64');
  const cred = new PublicKeyCredential(data.id, data.type, rawId, attestation);

  const domain = `https://${req.hostname}`;
  const rpId = req.hostname;
  switch (cred.getAttestationType()) {
    case FIDOU2F:
      U2fServer.registerCredential(cred, currentUser, session, domain, rpId);
      break;
    case ANDROIDSAFETYNET:
      AndroidSafetyNetServer.registerCredential(cred, currentUser, session, rpId);
      break;
    case PACKED:
      PackedServer.registerCredential(cred, currentUser, session, rpId);
      break;
  }

  const credential = new Credential(cred);
  credential.save(currentUser);

  const rsp = new PublicKeyCredentialResponse(true, "Successfully created credential");

  res.set('Content-Type', 'application/json')
  res.send(rsp.getJSON());
});
app.post('/BeginGetAssertion', sessionCheck, (req, res) => {

});
app.post('/FinishGetAssertion', sessionCheck, (req, res) => {

});
app.post('/RemoveCredential', sessionCheck, (req, res) => {

});
app.get('/', (req, res) => {
  // Temporarily assign session
  req.session.user = {
    id: 'agektmr',
    name: 'Eiji Kitamura'
  };
  // TODO: load template
  res.render('index');
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`serving from port ${PORT}`);
});