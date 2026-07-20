export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function backoffDelay(attempt, { baseMs = 1_000, maxMs = 60_000, random = Math.random } = {}) {
  const capped = Math.min(maxMs, baseMs * (2 ** Math.min(attempt, 10)));
  return Math.min(maxMs, Math.round(capped * (0.75 + random() * 0.5)));
}

export function normalizePhone(value) {
  return String(value ?? '').replace(/[^0-9]/g, '');
}

export function incomingMessage(message) {
  if (!message?.message || message.key?.fromMe || message.key?.remoteJid === 'status@broadcast') return null;
  let content = message.message;
  for (let depth = 0; depth < 5; depth += 1) {
    const wrapped = content.ephemeralMessage?.message
      ?? content.viewOnceMessage?.message
      ?? content.viewOnceMessageV2?.message
      ?? content.viewOnceMessageV2Extension?.message
      ?? content.documentWithCaptionMessage?.message;
    if (!wrapped) break;
    content = wrapped;
  }
  const body = content.conversation ?? content.extendedTextMessage?.text ?? content.imageMessage?.caption ?? content.videoMessage?.caption ?? '';
  const type = Object.keys(content)[0] ?? 'unknown';
  const senderJid = message.key.participant ?? message.key.remoteJid ?? '';
  const senderPhone = senderJid.endsWith('@lid') ? null : normalizePhone(senderJid.split('@')[0]);
  return {
    external_id: message.key?.id,
    sender_phone: senderPhone,
    body,
    received_at: new Date(Number(message.messageTimestamp ?? Math.floor(Date.now() / 1000)) * 1000).toISOString(),
    message_type: type,
    raw_metadata: { remote_jid: message.key?.remoteJid, participant: message.key?.participant, push_name: message.pushName }
  };
}

export function redact(value) {
  const sensitive = /token|authorization|secret|password|credential|qr/i;
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sensitive.test(key) ? '[REDACTED]' : redact(item)]));
}
