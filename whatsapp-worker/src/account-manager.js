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

function withTimeout(promise, timeoutMs, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

export class AccountManager {
  constructor({
    backend,
    authDir,
    logger,
    outbox,
    socketFactory = makeWASocket,
    authStateLoader = useMultiFileAuthState,
    makeDir = mkdir,
    removeDir = rm,
    logoutTimeoutMs = 15_000
  }) {
    this.backend = backend;
    this.authDir = authDir;
    this.logger = logger;
    this.outbox = outbox;
    this.socketFactory = socketFactory;
    this.authStateLoader = authStateLoader;
    this.makeDir = makeDir;
    this.removeDir = removeDir;
    this.logoutTimeoutMs = logoutTimeoutMs;
    this.accounts = new Map();
    this.completedLogoutCommands = new Map();
    this.nextEpoch = 1;
  }

  async reconcile(items) {
    const known = new Map(items.map((account) => [String(account.id), account]));
    for (const [id] of this.accounts) {
      const account = known.get(id);
      if (!account || (!account.enabled && !account.logout_command_id)) {
        await this.stop(id, 'disabled');
      }
    }

    for (const account of known.values()) {
      if (account.logout_command_id) await this.requestLogout(account);
    }
    for (const account of known.values()) {
      const id = String(account.id);
      if (account.enabled && !account.logout_command_id && !this.accounts.has(id)) {
        await this.start(account);
      }
    }
  }

  async start(account) {
    const id = String(account.id);
    if (this.accounts.has(id)) return;
    const entry = {
      account,
      socket: null,
      timer: null,
      stopped: false,
      attempts: 0,
      state: 'new',
      epoch: this.nextEpoch++,
      authLoaded: false,
      registered: false,
      connectionOpen: false,
      remoteLogoutComplete: false,
      saveCredsPromise: Promise.resolve(),
      eventPromise: Promise.resolve(),
      logoutPromise: null
    };
    this.accounts.set(id, entry);
    await this.connect(id, entry.epoch);
  }

  authPath(id) {
    if (!/^[0-9a-f-]{36}$/i.test(String(id))) throw new Error('invalid account id');
    return path.join(this.authDir, String(id));
  }

  async stop(id, state = 'disabled') {
    const entry = this.accounts.get(String(id));
    if (!entry) return;
    entry.stopped = true;
    clearTimeout(entry.timer);
    this.accounts.delete(String(id));
    try { entry.socket?.end?.(new Error(state)); } catch {}
    await this.safeState(id, { state });
    this.logger.info('account_stopped', { account_id: id, state });
  }

  async connect(id, epoch) {
    const entry = this.accounts.get(String(id));
    if (!entry || entry.stopped || entry.epoch !== epoch) return;
    try {
      const accountAuthPath = this.authPath(id);
      await this.makeDir(accountAuthPath, { recursive: true });
      const { state, saveCreds } = await this.authStateLoader(accountAuthPath);
      if (entry.stopped || this.accounts.get(String(id))?.epoch !== epoch) return;
      entry.authLoaded = true;
      entry.registered = Boolean(state.creds.registered);
      const socket = this.socketFactory({
        auth: state,
        printQRInTerminal: false,
        markOnlineOnConnect: false,
        logger: silentBaileysLogger
      });
      entry.socket = socket;
      socket.ev.on('creds.update', () => {
        entry.saveCredsPromise = entry.saveCredsPromise
          .then(() => saveCreds())
          .catch((error) => this.logger.error('credentials_save_failed', {
            account_id: id,
            error: error.name
          }));
      });
      socket.ev.on('connection.update', (update) => {
        entry.eventPromise = entry.eventPromise
          .then(() => this.onConnection(id, epoch, update))
          .catch((error) => this.logger.error('connection_event_failed', {
            account_id: id,
            error: error.name
          }));
      });
      socket.ev.on('messages.upsert', ({ type, messages }) => {
        if (type === 'notify') {
          for (const message of messages) this.onMessage(id, epoch, message);
        }
      });
      if (!entry.account.logout_command_id) {
        await this.safeState(id, {
          state: entry.registered ? 'connecting' : 'pending_qr'
        });
      }
    } catch (error) {
      this.logger.error('account_connect_failed', { account_id: id, error: error.name });
      this.schedule(id, epoch, 'connect_failed');
    }
  }

  async requestLogout(account) {
    const id = String(account.id);
    const commandId = String(account.logout_command_id);
    if (this.completedLogoutCommands.get(id) === commandId) {
      return this.ackLogout(id, commandId);
    }

    let entry = this.accounts.get(id);
    if (!entry) {
      await this.start(account);
      entry = this.accounts.get(id);
    }
    if (!entry || !entry.authLoaded) return false;
    entry.account = account;
    if (entry.registered && !entry.connectionOpen && !entry.remoteLogoutComplete) {
      return false;
    }
    if (entry.logoutPromise) return entry.logoutPromise;

    const operation = this.performLogout(id, entry, commandId);
    entry.logoutPromise = operation;
    try {
      return await operation;
    } finally {
      if (this.accounts.get(id) === entry) entry.logoutPromise = null;
    }
  }

  async performLogout(id, entry, commandId) {
    entry.stopped = true;
    clearTimeout(entry.timer);
    try {
      if (entry.registered && !entry.remoteLogoutComplete) {
        if (typeof entry.socket?.logout !== 'function') throw new Error('logout unavailable');
        await withTimeout(
          Promise.resolve(entry.socket.logout()),
          this.logoutTimeoutMs,
          'logout timed out'
        );
      }
      entry.remoteLogoutComplete = true;
      await entry.saveCredsPromise;
      try { entry.socket?.end?.(new Error('logout_requested')); } catch {}
      await this.removeDir(this.authPath(id), { recursive: true, force: true });
      if (this.accounts.get(id) === entry) this.accounts.delete(id);
      this.completedLogoutCommands.set(id, commandId);
      await this.ackLogout(id, commandId);
      this.logger.info('account_logout_completed', { account_id: id });
      return true;
    } catch (error) {
      this.logger.error('account_logout_failed', { account_id: id, error: error.name });
      if (!entry.remoteLogoutComplete) {
        await this.restartAfterLogoutFailure(id, entry);
      }
      return false;
    }
  }

  async restartAfterLogoutFailure(id, entry) {
    const oldSocket = entry.socket;
    entry.epoch = this.nextEpoch++;
    entry.stopped = false;
    entry.connectionOpen = false;
    entry.authLoaded = false;
    entry.registered = false;
    entry.socket = null;
    try { oldSocket?.end?.(new Error('logout_retry')); } catch {}
    await entry.saveCredsPromise;
    await this.connect(id, entry.epoch);
  }

  async ackLogout(id, commandId) {
    try {
      await this.backend.ackLogout(id, commandId);
      if (this.completedLogoutCommands.get(id) === commandId) {
        this.completedLogoutCommands.delete(id);
      }
      return true;
    } catch (error) {
      this.logger.error('logout_ack_failed', { account_id: id, error: error.name });
      return false;
    }
  }

  async onConnection(id, epoch, update) {
    const entry = this.accounts.get(String(id));
    if (!entry || entry.stopped || entry.epoch !== epoch) return;
    if (update.qr) await this.safeState(id, { state: 'pending_qr', qr_code: update.qr });
    if (update.connection === 'open') {
      entry.connectionOpen = true;
      entry.attempts = 0;
      if (entry.account.logout_command_id) {
        await this.requestLogout(entry.account);
      } else {
        await this.safeState(id, {
          state: 'online',
          account_name: entry.socket?.user?.name ?? entry.socket?.user?.verifiedName ?? null
        });
        this.logger.info('account_online', { account_id: id });
      }
    }
    if (update.connection === 'close') {
      entry.connectionOpen = false;
      const code = new Boom(update.lastDisconnect?.error)?.output?.statusCode;
      if (code === DisconnectReason.loggedOut) {
        entry.stopped = true;
        this.accounts.delete(String(id));
        await entry.saveCredsPromise;
        await this.removeDir(this.authPath(id), { recursive: true, force: true });
        await this.safeState(id, { state: 'logged_out', last_error: 'session_logged_out' });
        this.logger.warn('account_logged_out', { account_id: id });
        return;
      }
      this.schedule(id, epoch, 'connection_closed');
    }
  }

  async onMessage(id, epoch, message) {
    const entry = this.accounts.get(String(id));
    if (!entry || entry.stopped || entry.epoch !== epoch) return;
    const item = incomingMessage(message);
    if (!item?.external_id) return;
    try {
      await this.outbox.enqueue({ account_id: id, ...item });
    } catch (error) {
      this.logger.error('message_persist_failed', {
        account_id: id,
        external_id: item.external_id,
        error: error.name
      });
    }
  }

  schedule(id, epoch, reason) {
    const entry = this.accounts.get(String(id));
    if (!entry || entry.stopped || entry.epoch !== epoch || entry.timer) return;
    const delay = backoffDelay(entry.attempts++);
    this.safeState(id, { state: 'degraded', last_error: reason });
    this.logger.warn('account_reconnect_scheduled', {
      account_id: id,
      delay_ms: delay,
      reason
    });
    entry.timer = setTimeout(() => {
      entry.timer = null;
      this.connect(id, epoch);
    }, delay);
  }

  async safeState(id, state) {
    const entry = this.accounts.get(String(id));
    if (entry) entry.state = state.state;
    try {
      await this.backend.state(id, state);
    } catch (error) {
      this.logger.error('state_delivery_failed', { account_id: id, error: error.name });
    }
  }

  status() {
    return {
      managed_accounts: this.accounts.size,
      online_accounts: [...this.accounts.values()].filter((entry) => entry.state === 'online').length,
      pending_messages: this.outbox.pending,
      completed_logout_commands: this.completedLogoutCommands.size
    };
  }
}
