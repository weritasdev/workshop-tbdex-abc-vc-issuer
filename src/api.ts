import type { SignOptions } from '@web5/credentials'

import { VerifiableCredential } from '@web5/credentials'
import { createOAuthUserAuth } from '@octokit/auth-oauth-user'
import { Ed25519, Jose } from '@web5/crypto'
import { responseTime } from './middleware/response-time.js'
import { auditLogger } from './middleware/audit-logger.js'
import { JwtVerifier } from './jwt-verifier.js'
import { register } from 'prom-client'
import { Octokit } from '@octokit/core'
import { config } from './config.js'


import express from 'express'
import cors from 'cors'


export const api = express()
api.use(cors())
api.use(responseTime)

//! Note: uncomment to enable audit logging
// api.use(auditLogger)


api.get('/health', (_, res) => {
  return res.status(200).send()
})

api.get('/metrics', async (_req, res) => {
  try {
    res.set('Content-Type', register.contentType)
    res.end(await register.metrics())
  } catch (e) {
    res.status(500).end(e)
  }
})

api.get('/credential', async (req, res) => {
  const authzHeader = req.headers['authorization']
  if (!authzHeader) {
    return res.status(401).json({ errors: ['Authorization header required'] })
  }

  const [_, compactJwt] = authzHeader.split('Bearer ')

  if (!compactJwt) {
    return res.status(401).json({ errors: ['Malformed Authorization header. Expected: Bearer TOKEN_HERE'] })
  }

  try {
    const { signer, payload } = await JwtVerifier.verify(compactJwt)

    const octokit = new Octokit({
      authStrategy: createOAuthUserAuth,
      auth: {
        clientId: config.github.oauth.clientId,
        clientSecret: config.github.oauth.clientSecret,
        code: payload.jti,
      },
    })

    // TODO: handle errors
    const loginResponse = await octokit.request('GET /user')
    const credentialData = {
      username: loginResponse.data.login
    }

    const credential = VerifiableCredential.create('TBDeveloperCredential', config.did.did, signer, credentialData)

    const signingKeyJwk = config.did.keySet.verificationMethodKeys[0].privateKeyJwk
    const signingKey = await Jose.jwkToKey({ key: signingKeyJwk })
    const signCredential: SignOptions['signer'] = async (toSign) => {
      return Ed25519.sign({ data: toSign, key: signingKey.keyMaterial })
    }

    const signedCredential = await credential.sign({
      issuerDid: config.did.did,
      subjectDid: signer,
      kid: config.did.document.verificationMethod[0].id,
      signer: signCredential
    })

    return res.status(201).json({ credential: signedCredential })

  } catch (e) {
    return res.status(401).json({ errors: [e.message] })
  }
})