'use client'
import {
    Card,
    CardContent,
    CardDescription,
    CardFooter,
    CardHeader,
    CardTitle,
} from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useEffect, useState } from 'react'
import { popupWindow } from '@/lib/utils'
import { createDPoPToken, generateKeyPair } from '@/lib/dpop'

export default function Home() {
    const [loading, setLoading] = useState(false);
    const [code, setCode] = useState<string>();
    const [accessToken, setAccessToken] = useState<string>('');
    const [keyPair, setKeyPair] = useState<CryptoKeyPair>();
    const [oauthStage, setOauthStage] = useState<number>(1);
    const [data, setData] = useState();

    const authorizationEndpoint = "http://localhost:4000/authorize";
    const resourceEndpoint = "http://localhost:3002/protected-resource";

    const handleLogin = async () => {

        if(!keyPair) return;

        const redirectURI = 'http://localhost:3000/callback';
        const scope = 'read write';

        const dpopToken = await createDPoPToken(keyPair, authorizationEndpoint, 'GET');

        const authUrl = `${authorizationEndpoint}?` +
            `response_type=code&` +
            `client_id=${encodeURIComponent('client_id')}&` +
            `redirect_uri=${encodeURIComponent(redirectURI)}&` +
            `scope=${encodeURIComponent(scope)}&` +
            `dpop=${encodeURIComponent(dpopToken)}`;

        window.location.href = authUrl;
    }

    const handleCallback = async () => {

        console.log("keypair",keyPair);
        console.log(code);  
        if(!keyPair || !code) return;

        const tokenEndPoint = 'http://localhost:4000/token';
        const clientId = 'client_id';
        const clientSecret = 'client_secret';
        const redirectUri = 'http://localhost:3000/callback';

        const dpopToken = await createDPoPToken(keyPair, tokenEndPoint, 'POST');

        try{
            // grant_type, code, client_id, client_secret
            const response = await fetch(tokenEndPoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'DPoP': dpopToken
                },
                body: new URLSearchParams(
                    {
                        grant_type: 'authorization_code',
                        code,
                        client_id: clientId,
                        client_secret: clientSecret,
                        redirect_uri: redirectUri
                    }
                )
            });

            const data = await response.json();
            // TODO: Token expiry and also refresh token mechanism
            setAccessToken(data.access_token);
            setOauthStage((oauthStage) => oauthStage + 1);
            console.log("got access token", accessToken);
        }
        catch(err){
            console.log("error occured while fetching access token", err);
        }


    }

    const handleAccessRoute = async () => {
        if(!accessToken || !keyPair){
            return;
        }

       const dpopToken = await createDPoPToken(keyPair, resourceEndpoint, 'GET');

       const response = await fetch(resourceEndpoint, {
        headers: {
            'Authorization': `DPoP ${accessToken}`,
            'DPoP': dpopToken
        }
       });

       const pData = await response.json();
       setData(pData);
       setOauthStage((oauthStage) => oauthStage + 1);
       console.log("Protected Resource", data);
    }

    // trying out skeleton from shadcn, setting time out for loading animation
    useEffect(() => {
        setLoading(true)
        setTimeout(() => setLoading(false), 500);

        async function init(){
            const kp = await generateKeyPair();
            setKeyPair(kp);
        }

        const searchParams = new URLSearchParams(window.location.search);
        const code = searchParams.get('code');
        console.log("searchparams", searchParams)
        if(code){
            setCode(code);
            setOauthStage(2);
        }
 
        init();            
        

    }, [])

    if (loading) {
        return (
            <div className="flex min-h-screen flex-col items-center justify-center p-24">
                <Skeleton className="h-[125px] w-[600px] rounded-xl" />
                <div className="space-y-2">
                    <Skeleton className="h-4 w-[600px]" />
                    <Skeleton className="h-4 w-[600px]" />
                </div>
            </div>
        )
    }

    return (
        <main className="flex min-h-screen flex-col items-center justify-center p-24">

            <div className='my-5 text-center'>
               Stage: {oauthStage}
               {(oauthStage === 2) && <div>Fetched Authorization Code: {code?.substring(0, 10)}</div>}
               {(oauthStage === 3) && <div>Fetched Access Token: {accessToken?.substring(0, 10)}</div>}
               {(oauthStage === 4) && <div>Fetched Protected Route Data: {JSON.stringify(data)}</div>}
            </div>
            <Card>
                <CardHeader>
                    <CardTitle>
                        Oauth 2.0 - Demonstrating Proof of Posession
                    </CardTitle>
                    <CardDescription>
                        Demo showcasing oauth2.0 implementation using dpop
                        headers
                    </CardDescription>
                </CardHeader>
                <div className="flex justify-center items-center">
                    <CardContent>
                        <Button onClick={handleLogin}>Login</Button>
                    </CardContent>
                    <CardContent>
                        <Button onClick={handleCallback}>Fetch Access Token</Button>
                    </CardContent>
                    <CardFooter>
                        <Button variant="outline" onClick={handleAccessRoute}>
                            Access Protected Route
                        </Button>
                    </CardFooter>
                </div>
            </Card>
        </main>
    )
}
