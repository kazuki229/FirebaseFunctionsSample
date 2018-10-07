import * as functions from 'firebase-functions';
import * as rp from 'request-promise';
import * as jwt from 'jsonwebtoken';
import * as admin from 'firebase-admin';
import * as jwksClient from 'jwks-rsa';

if (!admin.apps.length) {
  admin.initializeApp();
}

// // Start writing Firebase Functions
// // https://firebase.google.com/docs/functions/typescript
//
export const issueToken = functions.https.onRequest(async (request, response) => {
  const code = request.query.code;
  // TODO: fetch token endpoint from well-known endpoint
  const options = {
    'url': 'https://auth.login.yahoo.co.jp/yconnect/v2/token',
    'method': 'POST',
    'form': {
      'grant_type': 'authorization_code',
      'redirect_uri': functions.config().yahoojapan.redirect_uri,
      'code': code,
      'client_id': functions.config().yahoojapan.client_id
    }
  };

  const rpResponse = await rp(options).catch(error => {
    // TODO: error handling
    console.log(error);
  });

  const json = JSON.parse(rpResponse);
  // TODO: error handling for empty id_token
  const idToken: string = json.id_token;

  const client = jwksClient({
    jwksUri: 'https://auth.login.yahoo.co.jp/yconnect/v2/jwks'
  });

  const decoded = jwt.decode(idToken, { complete: true });

  const key = await getSigningKey(client, decoded['header']['kid']).catch(error => {
    // TODO: error handling
    console.log(error);
  });

  const verifyOptions = {
    'algorithm': 'RS256',
    'audience': functions.config().yahoojapan.client_id,
    'issuer': 'https://auth.login.yahoo.co.jp/yconnect/v2'
  }

  const jwtDecoded = await verify(idToken, key, verifyOptions).catch(error => {
    // TODO: error handling
    console.log(error);
  });

  const uid = 'yahoojapan:' + jwtDecoded['sub'];
  const customToken = await admin.auth().createCustomToken(uid).catch(error => {
    // TODO: error handling
    console.log(error);
  });

  response.contentType('application/json');
  response.send(JSON.stringify({
    'token': customToken
  }));
});

const getSigningKey = (client: jwksClient.JwksClient, kid: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    client.getSigningKey(kid, (error, key) => {
      if (error) {
        return reject(error);
      }
      const signingKey = key.publicKey || key.rsaPublicKey;
      return resolve(signingKey);
    });
  });
};

const verify = (idToken, signingKey, verifyOptions): Promise<string | object> => {
  return new Promise((resolve, reject) => {
    jwt.verify(idToken, signingKey, verifyOptions, (error, decoded) => {
      if (error) {
        return reject(error);
      }
      return resolve(decoded);
    });
  });
}
