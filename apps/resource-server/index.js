import express from 'express'
import jwt from 'jsonwebtoken'
import cors from 'cors'
import jwkPem from 'jwk-to-pem'

const app = express();
app.use(cors());

const accessTokens = new Map();

app.get('/protected-resource', (req, res) => {
    const authHeader = req.headers.authorization;

    const dpop = req.headers.dpop;

    if(!authHeader || !authHeader.startsWith('DPoP')){
        return res.status(401).json({ error: 'Missing or invalid Authorization header'});
    }
    

    // Access token needs to be shared within servers
    // skipping access token check for now.
    const accessToken = authHeader.split(' ')[1];
    console.log("accessTokens", accessTokens)
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

        // Check if the 'htm' and 'htu' claims match the current request
        if (decodedDPoP.htm !== 'GET' || decodedDPoP.htu !== 'http://localhost:3002/protected-resource') {
            throw new Error('Invalid DPoP token claims');
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