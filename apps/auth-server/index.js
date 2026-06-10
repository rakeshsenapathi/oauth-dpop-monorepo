import express from 'express';
import bodyParser from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken'
import jwkPem from 'jwk-to-pem'
import cors from 'cors'
import crypto from 'crypto'
import { checkAndStoreJti } from './lib/jtiStore.js'

const app = express();
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(cors());

// TODO: store the data in database instead of fetching it from this object
const clients = {
    'client_id': {
        client_secret: 'client_secret',
        redirect_uris: ['http://localhost:3000/callback']
    }
};

const authorizationCodes = new Map();
const accessTokens = new Map();

function replayResponse(res) {
    // RFC 9449 §11.1 — replay detected → invalid_dpop_proof
    return res
        .status(401)
        .set('WWW-Authenticate', 'DPoP error="invalid_dpop_proof", error_description="DPoP proof JTI has already been used"')
        .json({ error: 'invalid_dpop_proof', error_description: 'DPoP proof JTI has already been used' });
}

//render ui to display to user to enter login credentials
app.get('/authorize', async (req, res) => {
    const {client_id, redirect_uri, scope, dpop} = req.query;
    // TODO: fetch this from database.
    if(!clients[client_id] || !clients[client_id].redirect_uris.includes(redirect_uri)){
        return res.status(400).send('Invalid client or redirect URI');
    }

    try{
        const decodedToken = jwt.decode(dpop, {complete: true});
        const jwk = decodedToken.header.jwk;
        if (!jwk) {
            throw new Error('Missing JWK in token header');
        }
        const publicKey = jwkPem(jwk);
        const decodedDPoP = jwt.verify(dpop, publicKey);

        if (!decodedDPoP.jti) {
            throw new Error('Missing jti claim in DPoP proof');
        }

        const isNew = await checkAndStoreJti(decodedDPoP.jti, client_id);
        if (!isNew) {
            return replayResponse(res);
        }

        const code = uuidv4();
        authorizationCodes.set(code, {client_id, redirect_uri, scope});
        res.redirect(`${redirect_uri}?code=${code}`);
    }
    catch(err){
        console.log('error occured while verifying dpop token', err);
        res.redirect(`${redirect_uri}`)
    }

});

app.post('/token', async (req, res) => {
    const { grant_type, code, client_id, client_secret } = req.body;
    const dpop = req.headers.dpop;
    const authCode = authorizationCodes.get(code);

    if(grant_type !== 'authorization_code'){
        return res.status(400).json({ error: 'Unsupport grant type'});
    }

    if(!clients[client_id] || clients[client_id].client_secret !== 'client_secret'){
        return res.status(400).json({error: 'Invalid client credentials'});
    }

    console.log("authcodes", authorizationCodes.size);
    console.log("auth code", code);

    if (!authCode || authCode.client_id !== 'client_id') {
        return res.status(400).json({ error: 'Invalid authorization code' });
    }

    try {
        const decodedToken = jwt.decode(dpop, {complete: true});
        const jwk = decodedToken.header.jwk;
        if (!jwk) {
            throw new Error('Missing JWK in token header');
        }
        const publicKey = jwkPem(jwk);
        const decodedDPoP = jwt.verify(dpop, publicKey, { algorithms: ['ES384'] });

        if (!decodedDPoP.jti) {
            throw new Error('Missing jti claim in DPoP proof');
        }

        const isNew = await checkAndStoreJti(decodedDPoP.jti, client_id);
        if (!isNew) {
            return replayResponse(res);
        }

        const accessToken = crypto.randomBytes(32).toString('hex');
        accessTokens.set(accessToken, { client_id, scope: authCode.scope });
        authorizationCodes.delete(code);

        return res.json({
            access_token: accessToken,
            token_type: 'DPoP',
            expires_in: 3600,
            scope: authCode.scope
        });
    } catch (error) {
        console.log('err', error);
        return res.status(400).json({ error: 'Invalid DPoP token' });
    }

});

app.listen(4000, () => {
    console.log("listening at port", 4000);
});
