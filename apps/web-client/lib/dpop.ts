import { Base64 } from "./base64";

export async function generateKeyPair(){
    return await window.crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384'},
        false,
        ['sign', 'verify']
    )
};

export async function createDPoPToken(keyPair:CryptoKeyPair, htu: string, htm: string, nonce = null) {

    const header = {
        type: 'dpop+jwt',
        alg: 'ES384',
        jwk: await extractPublicJwk(keyPair.publicKey)
    }

    const payload = {
        jti: crypto.randomUUID(),
        htm,
        htu,
        iat: Math.floor(Date.now()/1000),
        exp: Math.floor(Date.now()/1000) + 120
    }

    // TODO: pass nonce
    if(nonce){
        payload[nonce] = nonce;
    }

    const encodedHeader = Base64.encodeURI(JSON.stringify(header));
    const encodedPayload = Base64.encodeURI(JSON.stringify(payload));

    const toSign = `${encodedHeader}.${encodedPayload}`;

    const signature = await window.crypto.subtle.sign(
        { name: 'ECDSA', hash: {name: 'SHA-384'} },
        keyPair.privateKey,
        new TextEncoder().encode(toSign)
    );

    // Convert Uint8Array to a regular array of numbers
    const byteArray = Array.from(new Uint8Array(signature));

    // Convert the array of numbers to a binary string
    const binaryString = String.fromCharCode.apply(null, byteArray);

    // Base64 encode the binary string (standard Base64)
    const base64Signature = btoa(binaryString);

    // Make the Base64 string URL-safe
    const base64UrlSignature = base64Signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');


    return `${encodedHeader}.${encodedPayload}.${base64UrlSignature}`
}

async function extractPublicJwk(publicKey: CryptoKey){
    const jwk = await window.crypto.subtle.exportKey('jwk', publicKey);
    return {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y
    }
}