import * as functions from 'firebase-functions';
import * as rp from 'request-promise';
import * as jwt from 'jsonwebtoken';
import * as admin from 'firebase-admin';
import * as jwksClient from 'jwks-rsa';

if (!admin.apps.length) {
  admin.initializeApp();
}

function getSigningKey(client: jwksClient.JwksClient, kid: string): Promise<string> {
  return new Promise((resolve, reject) => {
    client.getSigningKey(kid, (error, key) => {
      if (error) {
        reject(error);
        return;
      }
      const signingKey = key.publicKey || key.rsaPublicKey;
      resolve(signingKey);
    });
  });
};

function verify(idToken, signingKey, verifyOptions): Promise<string | object> {
  return new Promise((resolve, reject) => {
    jwt.verify(idToken, signingKey, verifyOptions, (error, decoded) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(decoded);
    });
  });
}

/**
 * Look up Firebase user based on Yahoo! JAPAN's mid. If the Firebase user does not exist,
 + fetch Yahoo! JAPAN profile and create a new Firebase user with it.
 *
 * @returns {Promise<UserRecord>} The Firebase user record in a promise.
 */
function getFirebaseUser(uid, accessToken) {
  const getProfileOptions = {
    url: 'https://userinfo.yahooapis.jp/yconnect/v2/attribute',
    headers: {
      Authorization: 'Bearer ' + accessToken
    },
  }

  return admin.auth().getUser(uid).catch(error => {
    if (error.code === 'auth/user-not-found') {
      return rp(getProfileOptions).then(response => {
        const json = JSON.parse(response);
        const displayName: string = json.nickname;
        const photoURL: string = json.picture;
        const email: string = json.email;
        const emailVerified: boolean = json.email_verified;
        // Create a new Firebase user with Yahoo! JAPAN profile and return it
        return admin.auth().createUser({
          uid: uid,
          displayName: displayName,
          photoURL: photoURL,
          email: email,
          emailVerified: emailVerified
        });
      });
    }
    // If error other than auth/user-not-found occurred, fail the whole login process
    throw error;
  });
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
  const user: admin.auth.UserRecord = await getFirebaseUser(uid, json.access_token).catch(error => {
    // TODO: error handling
    console.log(error);
  });
  console.log(user);

  const customToken = await admin.auth().createCustomToken(user.uid)
    .catch(error => {
      // TODO: error handling
      console.log(error);
    });

  response.contentType('application/json');
  response.send(JSON.stringify({
    'token': customToken
  }));
});
