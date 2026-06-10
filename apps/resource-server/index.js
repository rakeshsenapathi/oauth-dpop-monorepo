import express from 'express'
import jwt from 'jsonwebtoken'
import cors from 'cors'
import jwkPem from 'jwk-to-pem'
import crypto from 'crypto'
import { checkAndStoreJti } from './lib/jtiStore.js'

const app = express();
app.use(cors());

const accessTokens = new Map();

// RFC 9449 §4.2 — base64url(SHA-256(ASCII(access_token)))
function computeAth(accessToken) {
    return crypto.createHash('sha256').update(accessToken, 'ascii').digest().toString('base64url');
}

app.get('/protected-resource', async (req, res) => {
    const authHeader = req.headers.authorization;
    const dpop = req.headers.dpop;

    if(!authHeader || !authHeader.startsWith('DPoP')){
        return res.status(401).json({ error: 'Missing or invalid Authorization header'});
    }

    // Access token needs to be shared within servers
    // skipping access token check against store for now.
    const accessToken = authHeader.split(' ')[1];
    console.log("accessToken", accessToken)

    // if (!accessTokens.has(accessToken)) {
    //     return res.status(401).json({ error: 'Invalid access token' });
    // }

    try{
        const decodedToken = jwt.decode(dpop, {complete: true});
        const jwk = decodedToken.header.jwk;
        if (!jwk) {
            throw new Error('Missing JWK in token header');
        }
        const publicKey = jwkPem(jwk);
        const decodedDPoP = jwt.verify(dpop, publicKey, { algorithms: ['ES384'] });

        if (decodedDPoP.htm !== 'GET' || decodedDPoP.htu !== 'http://localhost:3002/protected-resource') {
            throw new Error('Invalid DPoP token claims');
        }

        if (!decodedDPoP.jti) {
            throw new Error('Missing jti claim in DPoP proof');
        }

        // Verify ath claim binds this proof to the presented access token (RFC 9449 §4.2)
        if (!decodedDPoP.ath) {
            return res.status(401)
                .set('WWW-Authenticate', 'DPoP error="invalid_dpop_proof", error_description="Missing ath claim"')
                .json({ error: 'invalid_dpop_proof', error_description: 'Missing ath claim' });
        }
        const expectedAth = computeAth(accessToken);
        if (decodedDPoP.ath !== expectedAth) {
            return res.status(401)
                .set('WWW-Authenticate', 'DPoP error="invalid_dpop_proof", error_description="ath mismatch"')
                .json({ error: 'invalid_dpop_proof', error_description: 'ath mismatch — proof is not bound to the presented access token' });
        }

        // Atomic SET NX EX — store ath as value so stored entries are self-describing
        const isNew = await checkAndStoreJti(decodedDPoP.jti, decodedDPoP.ath);
        if (!isNew) {
            return res.status(401)
                .set('WWW-Authenticate', 'DPoP error="invalid_dpop_proof", error_description="DPoP proof JTI has already been used"')
                .json({ error: 'invalid_dpop_proof', error_description: 'DPoP proof JTI has already been used' });
        }

        res.json({ message: 'This is a protected resource', data: 'Secret information' + Date.now() });
    }
    catch (error) {
        console.log('error', error);
        return res.status(401).json({ error: 'Invalid DPoP token' });
    }
})

app.listen(3002, () => {
    console.log('Resource server listening on port 3002');
});
