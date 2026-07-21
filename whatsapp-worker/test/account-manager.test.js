import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import path from 'node:path';
import { AccountManager } from '../src/account-manager.js';

const accountId = '11111111-1111-4111-8111-111111111111';
const commandId = '22222222-2222-4222-8222-222222222222';

function harness({ logoutError = null, ackFailures = 0, registered = true, registeredSequence = null } = {}) {
  const calls = { logout: 0, end: 0, removed: [], ack: [], states: [], sockets: 0, emitters: [] };
  let remainingAckFailures = ackFailures;
  let authLoads = 0;
  const backend = {
    async state(id, payload) { calls.states.push({ id, payload }); },
    async ackLogout(id, command) {
      calls.ack.push({ id, command });
      if (remainingAckFailures > 0) {
        remainingAckFailures -= 1;
        throw new Error('backend unavailable');
      }
    }
  };
  const manager = new AccountManager({
    backend,
    authDir: '/sessions',
    logger: { info() {}, warn() {}, error() {} },
    outbox: { pending: 0, async enqueue() {} },
    socketFactory: () => {
      calls.sockets += 1;
      const emitter = new EventEmitter();
      calls.emitters.push(emitter);
      return {
        ev: emitter,
        async logout() {
          calls.logout += 1;
          if (logoutError) throw logoutError;
        },
        end() { calls.end += 1; }
      };
    },
    authStateLoader: async () => ({
      state: {
        creds: {
          registered: registeredSequence
            ? registeredSequence[Math.min(authLoads++, registeredSequence.length - 1)]
            : registered
        }
      },
      saveCreds: async () => {}
    }),
    makeDir: async () => {},
    removeDir: async (target) => { calls.removed.push(target); },
    logoutTimeoutMs: 100
  });
  return { manager, calls };
}

async function openCurrentSocket(manager, calls) {
  const entry = manager.accounts.get(accountId);
  assert.ok(entry);
  calls.emitters.at(-1).emit('connection.update', { connection: 'open' });
  await entry.eventPromise;
}

function pendingAccount() {
  return {
    id: accountId,
    enabled: true,
    logout_command_id: commandId
  };
}

test('durable logout unlinks registered socket, wipes only account auth and acknowledges', async () => {
  const { manager, calls } = harness();
  await manager.reconcile([pendingAccount()]);
  assert.equal(calls.logout, 0);
  await openCurrentSocket(manager, calls);
  assert.equal(calls.logout, 1);
  assert.equal(calls.end, 1);
  assert.deepEqual(calls.removed, [path.join('/sessions', accountId)]);
  assert.deepEqual(calls.ack, [{ id: accountId, command: commandId }]);
  assert.equal(manager.accounts.size, 0);
  assert.equal(manager.completedLogoutCommands.size, 0);
});

test('logout failure preserves auth state and retries without acknowledging', async () => {
  const { manager, calls } = harness({ logoutError: new Error('offline') });
  await manager.reconcile([pendingAccount()]);
  await openCurrentSocket(manager, calls);
  assert.equal(calls.logout, 1);
  assert.deepEqual(calls.removed, []);
  assert.deepEqual(calls.ack, []);
  assert.equal(manager.accounts.size, 1);

  await manager.reconcile([pendingAccount()]);
  await openCurrentSocket(manager, calls);
  assert.equal(calls.logout, 2);
  assert.deepEqual(calls.removed, []);
  assert.deepEqual(calls.ack, []);
});

test('failed acknowledgement is retried without repeating remote logout', async () => {
  const { manager, calls } = harness({ ackFailures: 1 });
  await manager.reconcile([pendingAccount()]);
  await openCurrentSocket(manager, calls);
  assert.equal(calls.logout, 1);
  assert.equal(calls.ack.length, 1);
  assert.equal(manager.completedLogoutCommands.get(accountId), commandId);

  await manager.reconcile([pendingAccount()]);
  assert.equal(calls.logout, 1);
  assert.equal(calls.ack.length, 2);
  assert.equal(manager.completedLogoutCommands.size, 0);
});

test('unregistered pending-QR session is wiped without a remote logout call', async () => {
  const { manager, calls } = harness({ registered: false });
  await manager.reconcile([pendingAccount()]);
  assert.equal(calls.logout, 0);
  assert.deepEqual(calls.removed, [path.join('/sessions', accountId)]);
  assert.equal(calls.ack.length, 1);
});

test('next poll starts a clean session and requests a fresh QR after acknowledgement', async () => {
  const { manager, calls } = harness({ registeredSequence: [true, false] });
  await manager.reconcile([pendingAccount()]);
  await openCurrentSocket(manager, calls);
  await manager.reconcile([{ id: accountId, enabled: true, logout_command_id: null }]);
  assert.equal(calls.logout, 1);
  assert.equal(calls.sockets, 2);
  assert.equal(calls.states.at(-1).payload.state, 'pending_qr');
  assert.equal(manager.accounts.size, 1);
});
