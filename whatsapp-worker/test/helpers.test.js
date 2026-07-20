import test from 'node:test';
import assert from 'node:assert/strict';
import { backoffDelay, incomingMessage, normalizePhone, redact } from '../src/helpers.js';

test('normalizes phone numbers', () => assert.equal(normalizePhone('+7 (777) 123-45-67'), '77771234567'));
test('backoff is bounded and deterministic with injected random', () => { assert.equal(backoffDelay(0, { random: () => 0 }), 750); assert.equal(backoffDelay(99, { maxMs: 10000, random: () => 1 }), 10000); });
test('extracts only incoming user messages', () => { const item = incomingMessage({ key: { id: 'abc', remoteJid: '777@s.whatsapp.net', fromMe: false }, messageTimestamp: 1, message: { conversation: 'hello' } }); assert.equal(item.body, 'hello'); assert.equal(item.sender_phone, '777'); assert.equal(incomingMessage({ key: { fromMe: true }, message: { conversation: 'no' } }), null); });
test('unwraps ephemeral text and does not treat LID as a phone', () => { const item = incomingMessage({ key: { id: 'wrapped', remoteJid: '123456789@lid' }, messageTimestamp: 1, message: { ephemeralMessage: { message: { extendedTextMessage: { text: 'inside' } } } } }); assert.equal(item.body, 'inside'); assert.equal(item.message_type, 'extendedTextMessage'); assert.equal(item.sender_phone, null); });
test('redacts nested secrets', () => assert.deepEqual(redact({ token: 'x', ok: { qr_code: 'y', value: 1 } }), { token: '[REDACTED]', ok: { qr_code: '[REDACTED]', value: 1 } }));
