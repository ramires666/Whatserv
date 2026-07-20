import http from 'node:http';
import { BackendClient } from './backend.js';
import { AccountManager } from './account-manager.js';
import { createLogger } from './logger.js';
import { MessageOutbox } from './outbox.js';

const required = ['BACKEND_INTERNAL_URL', 'INTERNAL_API_TOKEN'];
for (const name of required) if (!process.env[name]) throw new Error(`${name} is required`);
const config = { authDir: process.env.WA_SESSION_DIR ?? './auth', healthPort: Number(process.env.WA_HEALTH_PORT ?? 3000), reconcileInterval: Number(process.env.WA_RECONCILE_INTERVAL_MS ?? 15_000) };
const logger = createLogger(process.env.LOG_LEVEL);
const backend = new BackendClient({ baseUrl: process.env.BACKEND_INTERNAL_URL, token: process.env.INTERNAL_API_TOKEN, logger });
const outbox = new MessageOutbox({ directory: `${config.authDir}/_outbox`, backend, logger });
await outbox.init();
const manager = new AccountManager({ backend, authDir: config.authDir, logger, outbox });
let healthy = false;
async function reconcile() { try { await manager.reconcile(await backend.accounts()); await outbox.flush(); healthy = true; } catch (error) { healthy = false; logger.error('reconcile_failed', { error: error.message }); } }
const server = http.createServer((req, res) => { if (req.url !== '/healthz') { res.writeHead(404).end(); return; } res.writeHead(healthy ? 200 : 503, { 'content-type': 'application/json' }); res.end(JSON.stringify({ status: healthy ? 'ok' : 'degraded', ...manager.status() })); });
server.listen(config.healthPort, () => logger.info('health_server_started', { port: config.healthPort }));
await reconcile();
const interval = setInterval(reconcile, config.reconcileInterval);
async function shutdown(signal) { logger.info('shutdown_started', { signal }); clearInterval(interval); server.close(); await Promise.all([...manager.accounts.keys()].map((id) => manager.stop(id, 'stopped'))); process.exit(0); }
process.on('SIGINT', () => shutdown('SIGINT')); process.on('SIGTERM', () => shutdown('SIGTERM'));
