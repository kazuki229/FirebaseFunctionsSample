import * as functions from 'firebase-functions'
import * as rp from 'request-promise'
import * as jwt from 'jsonwebtoken'
import * as admin from 'firebase-admin'
import * as jwksClient from 'jwks-rsa'
import * as crypto from 'crypto'
import * as base64url from 'base64url'
import * as secureRandom from 'secure-random'

if (!admin.apps.length) {
  admin.initializeApp()
}

function getSigningKey(client: jwksClient.JwksClient, kid: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
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

function verify(idToken: string, signingKey: string | Buffer, verifyOptions: jwt.VerifyOptions): Promise<string | object> {
  return new Promise<string | object>((resolve, reject) => {
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
async function getFirebaseUser(uid, accessToken, openidConfiguration) {
  return admin.auth().getUser(uid).catch(async error => {
    if (error.code === 'auth/user-not-found') {
      const response = await rp({
        url: openidConfiguration.userinfo_endpoint,
        headers: {
          Authorization: 'Bearer ' + accessToken
        },
        json: true,
      })

      return admin.auth().createUser({
        uid: uid,
        displayName: response.nickname as string,
        photoURL: response.picture as string,
        email: response.email as string,
        emailVerified: response.email_verified as boolean
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

  const openidConfiguration = await rp({
    url: 'https://auth.login.yahoo.co.jp/yconnect/v2/.well-known/openid-configuration',
    method: 'GET',
    json: true
  }).catch(error => {
    console.log(error)
  })

  const options = {
    url: openidConfiguration.token_endpoint,
    method: 'POST',
    form: {
      grant_type: 'authorization_code',
      redirect_uri: functions.config().yahoojapan.redirect_uri,
      code: code,
      client_id: functions.config().yahoojapan.client_id
    },
    json: true
  }

  const tokenResponse = await rp(options).catch(error => {
    // TODO: error handling
    console.log(error)
  })

  // Token Response Validation
  // http://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation
  // ID Token Validation(https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
  // - The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
  // - The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
  // - If the ID Token is received via direct communication between the Client and the Token Endpoint (which it is in this flow), the TLS server validation MAY be used to validate the issuer in place of checking the token signature. The Client MUST validate the signature of all other ID Tokens according to JWS [JWS] using the algorithm specified in the JWT alg Header Parameter. The Client MUST use the keys provided by the Issuer.
  // - The alg value SHOULD be the default of RS256 or the algorithm sent by the Client in the id_token_signed_response_alg parameter during Registration.
  // - The current time MUST be before the time represented by the exp Claim.
  // - The iat Claim can be used to reject tokens that were issued too far away from the current time, limiting the amount of time that nonces need to be stored to prevent attacks. The acceptable range is Client specific.
  // - If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present and its value checked to verify that it is the same value as the one that was sent in the Authentication Request. The Client SHOULD check the nonce value for replay attacks. The precise method for detecting replay attacks is Client specific.

  const idToken: string = tokenResponse.id_token
  const decoded = jwt.decode(idToken, { complete: true })

  if (decoded['header']['alg'] !== 'RS256') {
    console.log('alg is not RS256')
  }

  const jwksClientObj: jwksClient.JwksClient = jwksClient({
    jwksUri: openidConfiguration.jwks_uri
  })

  const key: string = await getSigningKey(jwksClientObj, decoded['header']['kid']).catch(error => {
    // TODO: error handling
    console.log(error)
    return '';
  })

  const verifyOptions = {
    algorithm: 'RS256',
    audience: functions.config().yahoojapan.client_id,
    issuer: openidConfiguration.issuer
  }

  const jwtDecoded = await verify(idToken, key, verifyOptions).catch(error => {
    // TODO: error handling
    console.log(error)
  })

  // Access Token Validation(http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation)
  const hash = crypto.createHash('sha256')
  hash.update(tokenResponse.access_token)
  const hashedAccessToken = hash.digest()
  const halfOfAccessToken = hashedAccessToken.slice(0, hashedAccessToken.length / 2)
  const atHashFromAccessToken = base64url(halfOfAccessToken)

  if (atHashFromAccessToken !== jwtDecoded['at_hash']) {
    console.log('at_hash is invalid.')
    return
  }

  const uid = 'yahoojapan:' + jwtDecoded['sub']
  const user: admin.auth.UserRecord = await getFirebaseUser(uid, tokenResponse.access_token, openidConfiguration).catch(error => {
    // TODO: error handling
    console.log(error)
    return null
  })
  console.log(user)

  const customToken = await admin.auth().createCustomToken(user.uid).catch(error => {
    // TODO: error handling
    console.log(error)
  })

  response.contentType('application/json')
  response.send(JSON.stringify({
    'token': customToken
  }))
})

export const generateNonce = functions.https.onRequest(async (request, response) => {
  const bytes = secureRandom(32, { type: 'Buffer' })
  const encoded = base64url(bytes)
  response.contentType('application/json')
  response.send(JSON.stringify({
    'nonce': encoded
  }))
})
