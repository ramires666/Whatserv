import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { MessageOutbox } from '../src/outbox.js';

const logger = { warn() {} };

test('outbox retains failed messages and removes acknowledged messages', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'whatserv-outbox-'));
  let shouldFail = true;
  const delivered = [];
  const backend = { async message(payload) { if (shouldFail) throw new Error('offline'); delivered.push(payload); } };
  const outbox = new MessageOutbox({ directory, backend, logger });
  try {
    await outbox.init();
    await outbox.enqueue({ external_id: 'm1' });
    assert.equal(outbox.pending, 1);
    assert.equal((await readdir(directory)).filter((name) => name.endsWith('.json')).length, 1);
    shouldFail = false;
    await outbox.flush();
    assert.deepEqual(delivered, [{ external_id: 'm1' }]);
    assert.equal(outbox.pending, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
