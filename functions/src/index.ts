import * as functions from 'firebase-functions'
import * as rp from 'request-promise'
import * as jwt from 'jsonwebtoken'
import * as admin from 'firebase-admin'
import * as jwksClient from 'jwks-rsa'
import * as crypto from 'crypto'
import * as base64url from 'base64url'

if (!admin.apps.length) {
  admin.initializeApp()
}

function getSigningKey(client: jwksClient.JwksClient, kid: string): Promise<string> {
  return new Promise((resolve, reject) => {
    client.getSigningKey(kid, (error, key) => {
      if (error) {
        reject(error)
        return
      }
      const signingKey = key.publicKey || key.rsaPublicKey
      resolve(signingKey)
    })
  })
}

function verify(idToken, signingKey, verifyOptions): Promise<string | object> {
  return new Promise((resolve, reject) => {
    jwt.verify(idToken, signingKey, verifyOptions, (error, decoded) => {
      if (error) {
        reject(error)
        return
      }
      resolve(decoded)
    })
  })
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
        const json = JSON.parse(response)
        const displayName: string = json.nickname
        const photoURL: string = json.picture
        const email: string = json.email
        const emailVerified: boolean = json.email_verified
        // Create a new Firebase user with Yahoo! JAPAN profile and return it
        return admin.auth().createUser({
          uid: uid,
          displayName: displayName,
          photoURL: photoURL,
          email: email,
          emailVerified: emailVerified
        })
      })
    }
    // If error other than auth/user-not-found occurred, fail the whole login process
    throw error
  })
}

// // Start writing Firebase Functions
// // https://firebase.google.com/docs/functions/typescript
//
export const issueToken = functions.https.onRequest(async (request, response) => {
  const code = request.query.code
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
  }

  const rpResponse = await rp(options).catch(error => {
    // TODO: error handling
    console.log(error)
  })

  // Token Response Validation
  // http://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation
  // 1. RFC6749
  // 1.1 https://tools.ietf.org/html/rfc6749#section-5.1

  const json = JSON.parse(rpResponse)
  // TODO: error handling for empty id_token
  const idToken: string = json.id_token

  const client = jwksClient({
    jwksUri: 'https://auth.login.yahoo.co.jp/yconnect/v2/jwks'
  })

  const decoded = jwt.decode(idToken, { complete: true })

  const key = await getSigningKey(client, decoded['header']['kid']).catch(error => {
    // TODO: error handling
    console.log(error)
  })

  // ID Token Validation(https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
  // - The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
  // - The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
  // - If the ID Token is received via direct communication between the Client and the Token Endpoint (which it is in this flow), the TLS server validation MAY be used to validate the issuer in place of checking the token signature. The Client MUST validate the signature of all other ID Tokens according to JWS [JWS] using the algorithm specified in the JWT alg Header Parameter. The Client MUST use the keys provided by the Issuer.
  // - The alg value SHOULD be the default of RS256 or the algorithm sent by the Client in the id_token_signed_response_alg parameter during Registration.
  // TODO check alg
  // - The current time MUST be before the time represented by the exp Claim.
  // - The iat Claim can be used to reject tokens that were issued too far away from the current time, limiting the amount of time that nonces need to be stored to prevent attacks. The acceptable range is Client specific.
  // - If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present and its value checked to verify that it is the same value as the one that was sent in the Authentication Request. The Client SHOULD check the nonce value for replay attacks. The precise method for detecting replay attacks is Client specific.
  const verifyOptions = {
    algorithm: 'RS256',
    audience: functions.config().yahoojapan.client_id,
    issuer: 'https://auth.login.yahoo.co.jp/yconnect/v2',
    maxAge: 30000
  }

  const jwtDecoded = await verify(idToken, key, verifyOptions).catch(error => {
    // TODO: error handling
    console.log(error)
  })

  // Access Token Validation(http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation)
  const hash = crypto.createHash('sha256')
  const decodeAccessToken = base64url.toBuffer(json.access_token)

  hash.update(json.access_token)
  const hashedAccessToken = hash.digest()
  const halfOfAccessToken = hashedAccessToken.slice(0, hashedAccessToken.length / 2)
  const atHashFromAccessToken = base64url(halfOfAccessToken)

  if (atHashFromAccessToken !== jwtDecoded['at_hash']) {
    console.log('at_hash is invalid.')
    return
  }

  const uid = 'yahoojapan:' + jwtDecoded['sub']
  const user: admin.auth.UserRecord = await getFirebaseUser(uid, json.access_token).catch(error => {
    // TODO: error handling
    console.log(error)
  })
  console.log(user)

  const customToken = await admin.auth().createCustomToken(user.uid)
    .catch(error => {
      // TODO: error handling
      console.log(error)
    })

  response.contentType('application/json')
  response.send(JSON.stringify({
    'token': customToken
  }))
})
