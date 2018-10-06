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
  var code = request.query.code;

  var options = {
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
    var json = JSON.parse(body);
    var idToken: string = json.id_token;

    var decoded = jwt.decode(idToken);

    var uid = 'yahoojapan:' + decoded['sub'];
    admin.auth().createCustomToken(uid)
    .then(function(customToken) {
      var returnJson = {
        'token': customToken
      }
      response.contentType('application/json');
      response.send(JSON.stringify(returnJson));
    })
    .catch(function(error) {

    })
  })
});
