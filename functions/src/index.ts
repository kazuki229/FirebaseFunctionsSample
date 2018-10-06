import * as functions from 'firebase-functions';
import * as httpRequest from 'request';
import * as jwt from 'jsonwebtoken';
import * as admin from 'firebase-admin';

if (!admin.apps.length) {
  admin.initializeApp();
}

// // Start writing Firebase Functions
// // https://firebase.google.com/docs/functions/typescript
//
export const issueToken = functions.https.onRequest((request, response) => {
  const code = request.query.code;

  const options = {
    'url': 'https://auth.login.yahoo.co.jp/yconnect/v2/token',
    'method': 'POST',
    'form': {
      'grant_type': 'authorization_code',
      'redirect_uri': process.env.YAHOOJAPAN_REDIRECT_URI,
      'code': code,
      'client_id': process.env.YAHOOJAPAN_CLIENT_ID
    }
  };

  httpRequest(options, function(error, httpResponse, body) {
    const json = JSON.parse(body);
    const idToken: string = json.id_token;

    const decoded = jwt.decode(idToken);

    const uid = 'yahoojapan:' + decoded['sub'];
    admin.auth().createCustomToken(uid)
    .then(function(customToken) {
      const returnJson = {
        'token': customToken
      }
      response.contentType('application/json');
      response.send(JSON.stringify(returnJson));
    })
    .catch(function(createCustomTokenError) {
      console.log(createCustomTokenError);
    })
  })
});
