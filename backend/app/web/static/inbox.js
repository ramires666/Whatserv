(() => {
  'use strict';

  const list = document.querySelector('#messages');
  const status = document.querySelector('#connection');
  const error = document.querySelector('#error');
  const code = document.querySelector('#totp-code');
  const countdownValue = document.querySelector('#countdown-value');
  const countdownRing = document.querySelector('#countdown-ring');
  const passwordNode = document.querySelector('#credential-password');
  const revealPasswordButton = document.querySelector('#reveal-password');
  const copyPasswordButton = document.querySelector('#copy-password');
  const circumference = 2 * Math.PI * 18;
  let expiresAt = 0;
  let period = 30;
  let busy = false;
  let currentTotp = '';
  let currentPassword = '';
  let passwordTimer = null;

  async function copyText(value) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (_) {
      const area = document.createElement('textarea');
      area.value = value;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.append(area);
      area.select();
      const copied = document.execCommand('copy');
      area.remove();
      return copied;
    }
  }

  function formatTime(value) {
    const date = new Date(value);
    if (Number.isNaN(date.valueOf())) return value || '';
    return new Intl.DateTimeFormat('ru', {
      dateStyle: 'medium', timeStyle: 'medium'
    }).format(date);
  }

  function hidePassword() {
    currentPassword = '';
    passwordNode.textContent = '••••••••••••';
    copyPasswordButton.disabled = true;
    revealPasswordButton.textContent = 'Показать пароль';
    clearTimeout(passwordTimer);
    passwordTimer = null;
  }

  countdownRing.style.strokeDasharray = String(circumference);
  for (const node of document.querySelectorAll('time.local-time')) {
    node.textContent = formatTime(node.dateTime);
  }

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
      const senderBlock = document.createElement('div');
      senderBlock.className = 'sender-details';
      const sender = document.createElement('strong');
      sender.textContent = message.sender_name || message.sender_phone || message.sender_jid || 'WhatsApp';
      senderBlock.append(sender);

      const details = [
        message.sender_name ? message.sender_phone : null,
        message.sender_jid,
        message.participant_jid && message.participant_jid !== message.sender_jid
          ? `участник: ${message.participant_jid}`
          : null
      ].filter(Boolean);
      if (details.length) {
        const senderMeta = document.createElement('small');
        senderMeta.textContent = details.join(' · ');
        senderBlock.append(senderMeta);
      }

      const time = document.createElement('time');
      time.dateTime = message.received_at;
      time.textContent = formatTime(message.received_at);
      time.title = message.received_at;
      header.append(senderBlock, time);

      const bodyValue = message.body || `[${message.message_type}]`;
      const body = document.createElement('button');
      body.type = 'button';
      body.className = 'message-body-copy';
      body.textContent = bodyValue;
      body.title = 'Нажмите, чтобы скопировать сообщение';
      body.addEventListener('click', async () => {
        const copied = await copyText(bodyValue);
        body.classList.toggle('copied', copied);
        setTimeout(() => body.classList.remove('copied'), 1000);
      });

      const footer = document.createElement('div');
      footer.className = 'message-footer';
      const technical = document.createElement('small');
      technical.textContent = `${message.message_type} · ${message.external_id}`;
      footer.append(technical);
      if (message.sender_phone) {
        const digits = message.sender_phone.replace(/\D/g, '');
        if (digits) {
          const reply = document.createElement('a');
          reply.className = 'ghost-button reply-link';
          reply.href = `https://wa.me/${encodeURIComponent(digits)}`;
          reply.target = '_blank';
          reply.rel = 'noopener noreferrer';
          reply.textContent = 'Написать в WhatsApp';
          footer.append(reply);
        }
      }

      item.append(header, body, footer);
      list.append(item);
    }
  }

  async function refresh() {
    if (busy) return;
    busy = true;
    const requestStartedAt = Date.now();
    try {
      const response = await fetch(document.body.dataset.snapshotUrl, {
        cache: 'no-store', credentials: 'same-origin'
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      setStatus(data.whatsapp_state);
      renderMessages(data.messages);
      if (data.totp) {
        const value = data.totp.code;
        currentTotp = value;
        code.textContent = value.length === 6 ? `${value.slice(0, 3)} ${value.slice(3)}` : value;
        code.disabled = false;
        period = data.totp.period;
        const serverTime = Date.parse(data.totp.server_time);
        const validUntil = Date.parse(data.totp.valid_until);
        const roundTrip = Date.now() - requestStartedAt;
        const serverRemaining = validUntil - serverTime;
        expiresAt = Date.now() + Math.max(0, serverRemaining - roundTrip);
      } else {
        currentTotp = '';
        code.textContent = 'НЕ НАСТРОЕН';
        code.disabled = true;
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
    if (remaining === 0) {
      expiresAt = 0;
      currentTotp = '';
      code.textContent = 'ОБНОВЛЯЕМ';
      code.disabled = true;
      void refresh();
    }
  }

  code.addEventListener('click', async () => {
    if (!currentTotp) return;
    const copied = await copyText(currentTotp);
    code.classList.toggle('copied', copied);
    setTimeout(() => code.classList.remove('copied'), 1000);
  });

  revealPasswordButton.addEventListener('click', async () => {
    if (currentPassword) {
      hidePassword();
      return;
    }
    revealPasswordButton.disabled = true;
    try {
      const response = await fetch(document.body.dataset.credentialsUrl, {
        cache: 'no-store', credentials: 'same-origin'
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const credentials = await response.json();
      currentPassword = credentials.password;
      passwordNode.textContent = currentPassword;
      copyPasswordButton.disabled = false;
      revealPasswordButton.textContent = 'Скрыть пароль';
      passwordTimer = setTimeout(hidePassword, 30_000);
    } catch (_) {
      passwordNode.textContent = 'НЕ УДАЛОСЬ ЗАГРУЗИТЬ';
    } finally {
      revealPasswordButton.disabled = false;
    }
  });

  copyPasswordButton.addEventListener('click', async () => {
    if (!currentPassword) return;
    copyPasswordButton.textContent = await copyText(currentPassword)
      ? 'Скопировано'
      : 'Ошибка копирования';
    setTimeout(() => { copyPasswordButton.textContent = 'Скопировать'; }, 1800);
  });

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) hidePassword();
  });
  window.addEventListener('pagehide', hidePassword);

  document.querySelector('#refresh').addEventListener('click', refresh);
  void refresh();
  setInterval(tick, 250);
  setInterval(refresh, 3000);
})();
