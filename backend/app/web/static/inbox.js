(() => {
  'use strict';

  const list = document.querySelector('#messages');
  const status = document.querySelector('#connection');
  const error = document.querySelector('#error');
  const code = document.querySelector('#totp-code');
  const countdownValue = document.querySelector('#countdown-value');
  const countdownRing = document.querySelector('#countdown-ring');
  const circumference = 2 * Math.PI * 18;
  let expiresAt = 0;
  let period = 30;
  let busy = false;

  countdownRing.style.strokeDasharray = String(circumference);

  function setStatus(value) {
    status.textContent = value || 'unknown';
    status.className = `status-pill status-${value || 'unknown'}`;
  }

  function renderMessages(messages) {
    list.replaceChildren();
    if (!messages.length) {
      const item = document.createElement('li');
      item.className = 'empty-state';
      item.textContent = 'Новых сообщений пока нет.';
      list.append(item);
      return;
    }
    for (const message of messages) {
      const item = document.createElement('li');
      item.className = 'message-card';
      const header = document.createElement('div');
      header.className = 'message-meta';
      const sender = document.createElement('strong');
      sender.textContent = message.sender_phone || 'WhatsApp';
      const time = document.createElement('time');
      time.dateTime = message.received_at;
      time.textContent = new Intl.DateTimeFormat('ru', { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(message.received_at));
      const body = document.createElement('p');
      body.textContent = message.body || `[${message.message_type}]`;
      header.append(sender, time);
      item.append(header, body);
      list.append(item);
    }
  }

  async function refresh() {
    if (busy) return;
    busy = true;
    try {
      const response = await fetch(document.body.dataset.snapshotUrl, { cache: 'no-store', credentials: 'same-origin' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      setStatus(data.whatsapp_state);
      renderMessages(data.messages);
      if (data.totp) {
        const value = data.totp.code;
        code.textContent = value.length === 6 ? `${value.slice(0, 3)} ${value.slice(3)}` : value;
        period = data.totp.period;
        expiresAt = Date.now() + data.totp.valid_for * 1000;
      } else {
        code.textContent = 'НЕ НАСТРОЕН';
        expiresAt = 0;
      }
      error.hidden = true;
    } catch (_) {
      error.textContent = 'Не удалось обновить данные. Повторяем попытку…';
      error.hidden = false;
    } finally {
      busy = false;
    }
  }

  function tick() {
    if (!expiresAt) {
      countdownValue.textContent = '—';
      countdownRing.style.strokeDashoffset = String(circumference);
      return;
    }
    const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    countdownValue.textContent = String(remaining);
    countdownRing.style.strokeDashoffset = String(circumference * (1 - remaining / period));
    if (remaining === 0) void refresh();
  }

  document.querySelector('#refresh').addEventListener('click', refresh);
  void refresh();
  setInterval(tick, 250);
  setInterval(refresh, 3000);
})();
