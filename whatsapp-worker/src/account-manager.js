import path from 'node:path';
import { mkdir, rm } from 'node:fs/promises';
import makeWASocket, { DisconnectReason, useMultiFileAuthState } from '@whiskeysockets/baileys';
import { Boom } from '@hapi/boom';
import { backoffDelay, incomingMessage } from './helpers.js';

const silentBaileysLogger = {
  level: 'silent',
  child() { return silentBaileysLogger; },
  trace() {},
  debug() {},
  info() {},
  warn() {},
  error() {},
  fatal() {}
};

export class AccountManager {
  constructor({ backend, authDir, logger, outbox, socketFactory = makeWASocket }) { this.backend = backend; this.authDir = authDir; this.logger = logger; this.outbox = outbox; this.socketFactory = socketFactory; this.accounts = new Map(); }
  async reconcile(items) {
    const wanted = new Map(items.filter((a) => a.enabled).map((a) => [String(a.id), a]));
    for (const [id, entry] of this.accounts) if (!wanted.has(id)) await this.stop(id, 'disabled');
    for (const [id, account] of wanted) if (!this.accounts.has(id)) await this.start(account);
  }
  async start(account) {
    const id = String(account.id); const entry = { account, socket: null, timer: null, stopped: false, attempts: 0, state: 'new' };
    this.accounts.set(id, entry); await this.connect(id);
  }
  authPath(id) {
    if (!/^[0-9a-f-]{36}$/i.test(String(id))) throw new Error('invalid account id');
    return path.join(this.authDir, String(id));
  }
  async stop(id, state = 'disabled') {
    const entry = this.accounts.get(String(id)); if (!entry) return;
    entry.stopped = true; clearTimeout(entry.timer); this.accounts.delete(String(id));
    try { entry.socket?.end?.(new Error(state)); } catch {}
    await this.safeState(id, { state }); this.logger.info('account_stopped', { account_id: id, state });
  }
  async connect(id) {
    const entry = this.accounts.get(String(id)); if (!entry || entry.stopped) return;
    try {
      const accountAuthPath = this.authPath(id);
      await mkdir(accountAuthPath, { recursive: true });
      const { state, saveCreds } = await useMultiFileAuthState(accountAuthPath);
      const socket = this.socketFactory({ auth: state, printQRInTerminal: false, markOnlineOnConnect: false, logger: silentBaileysLogger });
      entry.socket = socket;
      socket.ev.on('creds.update', () => saveCreds().catch((error) => this.logger.error('credentials_save_failed', { account_id: id, error: error.name })));
      socket.ev.on('connection.update', (update) => this.onConnection(id, update));
      socket.ev.on('messages.upsert', ({ type, messages }) => { if (type === 'notify') for (const message of messages) this.onMessage(id, message); });
      await this.safeState(id, { state: state.creds.registered ? 'connecting' : 'pending_qr' });
    } catch (error) { this.logger.error('account_connect_failed', { account_id: id, error: error.name }); this.schedule(id, 'connect_failed'); }
  }
  async onConnection(id, update) {
    const entry = this.accounts.get(String(id)); if (!entry || entry.stopped) return;
    if (update.qr) await this.safeState(id, { state: 'pending_qr', qr_code: update.qr });
    if (update.connection === 'open') { entry.attempts = 0; await this.safeState(id, { state: 'online' }); this.logger.info('account_online', { account_id: id }); }
    if (update.connection === 'close') {
      const code = new Boom(update.lastDisconnect?.error)?.output?.statusCode;
      if (code === DisconnectReason.loggedOut) {
        entry.stopped = true;
        this.accounts.delete(String(id));
        await rm(this.authPath(id), { recursive: true, force: true });
        await this.safeState(id, { state: 'logged_out', last_error: 'session_logged_out' });
        this.logger.warn('account_logged_out', { account_id: id });
        return;
      }
      this.schedule(id, 'connection_closed');
    }
  }
  async onMessage(id, message) { const item = incomingMessage(message); if (!item?.external_id) return; try { await this.outbox.enqueue({ account_id: id, ...item }); } catch (error) { this.logger.error('message_persist_failed', { account_id: id, external_id: item.external_id, error: error.name }); } }
  schedule(id, reason) { const entry = this.accounts.get(String(id)); if (!entry || entry.stopped || entry.timer) return; const delay = backoffDelay(entry.attempts++); this.safeState(id, { state: 'degraded', last_error: reason }); this.logger.warn('account_reconnect_scheduled', { account_id: id, delay_ms: delay, reason }); entry.timer = setTimeout(() => { entry.timer = null; this.connect(id); }, delay); }
  async safeState(id, state) { const entry = this.accounts.get(String(id)); if (entry) entry.state = state.state; try { await this.backend.state(id, state); } catch (error) { this.logger.error('state_delivery_failed', { account_id: id, error: error.name }); } }
  status() { return { managed_accounts: this.accounts.size, online_accounts: [...this.accounts.values()].filter((x) => x.state === 'online').length, pending_messages: this.outbox.pending }; }
}
