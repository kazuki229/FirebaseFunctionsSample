import * as functions from 'firebase-functions';
import * as httpRequest from 'request';
import * as jwt from 'jsonwebtoken';
import * as admin from 'firebase-admin';
import * as jwksClient from 'jwks-rsa';

if (!admin.apps.length) {
  admin.initializeApp();
}

// // Start writing Firebase Functions
// // https://firebase.google.com/docs/functions/typescript
//
export const issueToken = functions.https.onRequest((request, response) => {
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

  httpRequest(options, function(error, httpResponse, body) {
    // TODO: error handling
    const json = JSON.parse(body);

    // TODO: error handling for empty id_token
    const idToken: string = json.id_token;

    // TODO: verify IDToken
    const verifyOptions = {
      'algorithm': 'RS256',
      'audience': functions.config().yahoojapan.client_id,
      'issuer': 'https://auth.login.yahoo.co.jp/yconnect/v2'
    }

    const client = jwksClient({
      jwksUri: 'https://auth.login.yahoo.co.jp/yconnect/v2/jwks'
    });

    const decoded = jwt.decode(idToken, {complete: true});

    client.getSigningKey(decoded['header']['kid'], function(getSigningKeyError, key) {
      const signingKey = key.rsaPublicKey;

      jwt.verify(idToken, signingKey, verifyOptions, function(verifyError, jwtDecoded) {
        // TODO: error handling
        const uid = 'yahoojapan:' + jwtDecoded['sub'];
        admin.auth().createCustomToken(uid)
        .then(function(customToken) {
          const returnJson = {
            'token': customToken
          }
          response.contentType('application/json');
          response.send(JSON.stringify(returnJson));
        })
        .catch(function(createCustomTokenError) {
          // TODO: error handling
        })
      });
    });
  })
});
