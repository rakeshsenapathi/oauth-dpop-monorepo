import { NextRequest } from "next/server";
import { redirect } from 'next/navigation';

export async function GET(req: NextRequest) {

    const url = new URL(req.url);
    const searchParams = new URLSearchParams(url.search);
    const code = searchParams.get('code');

    redirect(`/?code=${code}`)
} 