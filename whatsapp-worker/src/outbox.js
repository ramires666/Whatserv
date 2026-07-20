import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { mkdir, readdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';

export class MessageOutbox {
  constructor({ directory, backend, logger }) {
    this.directory = directory;
    this.backend = backend;
    this.logger = logger;
    this.flushing = null;
    this.pending = 0;
  }

  async init() {
    await mkdir(this.directory, { recursive: true });
    await mkdir(path.join(this.directory, 'corrupt'), { recursive: true });
    this.pending = (await this.files()).length;
  }

  async files() {
    const names = await readdir(this.directory);
    return names.filter((name) => name.endsWith('.json')).sort();
  }

  async enqueue(payload) {
    const name = `${Date.now()}-${randomUUID()}.json`;
    const finalPath = path.join(this.directory, name);
    const temporaryPath = `${finalPath}.tmp`;
    await writeFile(temporaryPath, JSON.stringify(payload), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    await rename(temporaryPath, finalPath);
    this.pending += 1;
    await this.flush();
  }

  async flush() {
    if (this.flushing) return this.flushing;
    this.flushing = this.flushFiles().finally(() => { this.flushing = null; });
    return this.flushing;
  }

  async flushFiles() {
    for (const name of await this.files()) {
      const filePath = path.join(this.directory, name);
      let payload;
      try {
        payload = JSON.parse(await readFile(filePath, 'utf8'));
      } catch (error) {
        if (error instanceof SyntaxError) {
          await rename(filePath, path.join(this.directory, 'corrupt', name));
          this.pending = Math.max(0, this.pending - 1);
          this.logger.error?.('outbox_message_quarantined', { pending: this.pending });
          continue;
        }
        this.logger.warn('outbox_read_deferred', { error: error.name, pending: this.pending });
        break;
      }
      try {
        await this.backend.message(payload);
        await unlink(filePath);
        this.pending = Math.max(0, this.pending - 1);
      } catch (error) {
        this.logger.warn('outbox_delivery_deferred', { error: error.name, pending: this.pending });
        break;
      }
    }
  }
}
