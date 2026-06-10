import Redis from 'ioredis';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const JTI_TTL_SECONDS = 120;

let _client;

function getClient() {
    if (!_client) {
        _client = new Redis(REDIS_URL);
        _client.on('error', (err) => console.error('[Redis] error:', err.message));
        _client.on('connect', () => console.log('[Redis] connected'));
    }
    return _client;
}

/**
 * Atomically check and store a DPoP JTI using SET NX EX.
 *
 * Uses a single atomic command — no GET-then-SET race condition.
 *
 * @returns {Promise<boolean>} true = JTI is new (proceed); false = replay detected (reject)
 */
export async function checkAndStoreJti(jti, value, ttl = JTI_TTL_SECONDS) {
    const result = await getClient().set(`jti:${jti}`, value, 'EX', ttl, 'NX');
    return result === 'OK';
}
