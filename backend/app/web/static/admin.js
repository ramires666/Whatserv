(() => {
  'use strict';

  const createSecret = document.querySelector('#create-totp-secret');
  const withoutTotp = document.querySelector('#without-totp');
  const createForm = document.querySelector('#create-account');
  const createPhone = document.querySelector('#create-phone');
  const createWhatsappLogin = document.querySelector('[data-create-whatsapp-login]');
  const revealTimers = new Map();
  const openPanelsStorageKey = 'whatserv-admin-open-panels';
  let formDirty = false;

  async function copyText(value) {
    if (window.isSecureContext && navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(value);
        return true;
      } catch (_) {}
    }
    try {
      const area = document.createElement('textarea');
      area.value = value;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.append(area);
      area.focus();
      area.select();
      area.setSelectionRange(0, area.value.length);
      const copied = document.execCommand('copy');
      area.remove();
      return copied;
    } catch (_) { return false; }
  }

  function syncCreateTotpRequirement() {
    if (!createSecret || !withoutTotp) return;
    const disabled = withoutTotp.checked;
    createSecret.disabled = disabled;
    createSecret.required = !disabled;
    if (disabled) {
      createSecret.value = '';
      createSecret.type = 'password';
      const toggle = document.querySelector('[data-secret-toggle="create-totp-secret"]');
      if (toggle) {
        toggle.textContent = 'Показать';
        toggle.setAttribute('aria-label', 'Показать TOTP-секрет');
      }
    }
  }

  function syncCreateWhatsappLogin() {
    if (!createPhone || !createWhatsappLogin) return;
    createWhatsappLogin.hidden = !createPhone.value.trim();
  }

  function showCreateError(message) {
    let banner = document.querySelector('.error-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.className = 'error-banner';
      banner.setAttribute('role', 'alert');
      document.querySelector('.topbar')?.insertAdjacentElement('afterend', banner);
    }
    banner.textContent = message;
    document.querySelector('#create-account-panel').open = true;
    banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  createForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submitter = event.submitter;
    const formData = new FormData(createForm);
    if (submitter?.name) formData.set(submitter.name, submitter.value);
    for (const button of createForm.querySelectorAll('button[type="submit"]')) {
      button.disabled = true;
    }
    try {
      const response = await fetch(createForm.action, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin',
        redirect: 'follow'
      });
      if (response.ok) {
        window.location.assign(response.url || '/admin');
        return;
      }
      const responseBody = await response.text();
      const parsed = new DOMParser().parseFromString(responseBody, 'text/html');
      const message = parsed.querySelector('.error-banner')?.textContent?.trim()
        || `Не удалось сохранить аккаунт (HTTP ${response.status}).`;
      showCreateError(message);
    } catch (_) {
      showCreateError('Не удалось сохранить аккаунт: проверьте соединение и повторите попытку.');
    } finally {
      for (const button of createForm.querySelectorAll('button[type="submit"]')) {
        button.disabled = false;
      }
    }
  });

  for (const button of document.querySelectorAll('[data-secret-toggle]')) {
    button.addEventListener('click', () => {
      const input = document.getElementById(button.dataset.secretToggle);
      if (!input) return;
      const reveal = input.type === 'password';
      input.type = reveal ? 'text' : 'password';
      button.textContent = reveal ? 'Скрыть' : 'Показать';
      button.setAttribute('aria-label', reveal ? 'Скрыть TOTP-секрет' : 'Показать TOTP-секрет');
    });
  }

  for (const form of document.querySelectorAll('form[data-confirm]')) {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  }

  function copyButtonFor(targetId) {
    return document.querySelector(`[data-copy-target="${CSS.escape(targetId)}"]`);
  }

  function hideRevealedValue(targetId, revealButton) {
    const target = document.getElementById(targetId);
    if (!target) return;
    target.textContent = '••••••••••••';
    delete target.dataset.copyValue;
    const copyButton = copyButtonFor(targetId);
    if (copyButton) copyButton.disabled = true;
    if (revealButton) revealButton.textContent = 'Показать';
    clearTimeout(revealTimers.get(targetId));
    revealTimers.delete(targetId);
  }

  function scheduleHide(targetId, revealButton) {
    clearTimeout(revealTimers.get(targetId));
    revealTimers.set(targetId, setTimeout(() => {
      hideRevealedValue(targetId, revealButton);
    }, 30_000));
  }

  for (const button of document.querySelectorAll('[data-reveal-credentials]')) {
    button.addEventListener('click', async () => {
      const accountId = button.dataset.revealCredentials;
      const targetId = `admin-password-${accountId}`;
      const target = document.getElementById(targetId);
      const copyButton = copyButtonFor(targetId);
      if (!target || !copyButton) return;
      if (target?.dataset.copyValue) {
        hideRevealedValue(targetId, button);
        return;
      }
      button.disabled = true;
      try {
        const response = await fetch(`/admin/accounts/${encodeURIComponent(accountId)}/credentials`, {
          cache: 'no-store', credentials: 'same-origin'
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const credentials = await response.json();
        target.textContent = credentials.password;
        target.dataset.copyValue = credentials.password;
        copyButton.disabled = false;
        button.textContent = 'Скрыть';
        scheduleHide(targetId, button);
      } catch (_) {
        target.textContent = 'Не удалось получить пароль';
      } finally {
        button.disabled = false;
      }
    });
  }

  for (const button of document.querySelectorAll('[data-copy-target]')) {
    button.addEventListener('click', async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      const value = target?.dataset.copyValue;
      if (!value) return;
      try {
        button.textContent = await copyText(value) ? 'Скопировано' : 'Ошибка';
      } catch (_) { button.textContent = 'Ошибка'; }
      setTimeout(() => { button.textContent = 'Копировать'; }, 1800);
    });
  }

  for (const button of document.querySelectorAll('button[data-copy-value]')) {
    button.addEventListener('click', async () => {
      const original = button.textContent;
      button.textContent = await copyText(button.dataset.copyValue)
        ? 'Скопировано'
        : 'Выделите ссылку вручную';
      setTimeout(() => { button.textContent = original; }, 1800);
    });
  }

  for (const button of document.querySelectorAll('[data-open-details]')) {
    button.addEventListener('click', () => {
      const details = document.getElementById(button.dataset.openDetails);
      if (!details) return;
      const accountCard = details.closest('details.account-card');
      if (accountCard) accountCard.open = true;
      details.open = true;
      details.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      details.querySelector('input:not([type="hidden"]), textarea')?.focus();
    });
  }

  const persistentPanels = [...document.querySelectorAll('details.account-card')];
  try {
    const openPanelIds = new Set(JSON.parse(sessionStorage.getItem(openPanelsStorageKey) || '[]'));
    for (const panel of persistentPanels) {
      if (openPanelIds.has(panel.id)) panel.open = true;
    }
  } catch (_) {}
  function persistOpenPanels() {
    try {
      sessionStorage.setItem(
        openPanelsStorageKey,
        JSON.stringify(persistentPanels.filter((panel) => panel.open).map((panel) => panel.id))
      );
    } catch (_) {}
  }
  for (const panel of persistentPanels) {
    panel.addEventListener('toggle', persistOpenPanels);
  }

  function formatLocalTime(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.valueOf())) return value;
    return new Intl.DateTimeFormat('ru', {
      dateStyle: 'medium', timeStyle: 'medium'
    }).format(date);
  }

  for (const node of document.querySelectorAll('time.local-time')) {
    node.textContent = formatLocalTime(node.dateTime);
  }

  for (const button of document.querySelectorAll('.summary-copy')) {
    button.addEventListener('click', async () => {
      const value = button.dataset.copyValue;
      if (!value) return;
      const copied = await copyText(value);
      button.classList.toggle('copied', copied);
      setTimeout(() => button.classList.remove('copied'), 1000);
    });
  }

  async function refreshAccountSummaries() {
    try {
      const response = await fetch('/admin/account-summaries', {
        cache: 'no-store', credentials: 'same-origin'
      });
      if (!response.ok) return;
      const payload = await response.json();
      for (const item of payload.items) {
        const totpButton = document.querySelector(`[data-summary-totp="${CSS.escape(item.account_id)}"]`);
        if (totpButton) {
          const value = item.totp || '';
          totpButton.querySelector('strong').textContent = value.length === 6
            ? `${value.slice(0, 3)} ${value.slice(3)}`
            : 'НЕ НАСТРОЕН';
          totpButton.dataset.copyValue = value;
          totpButton.disabled = !value;
        }
        const messageButton = document.querySelector(`[data-summary-message="${CSS.escape(item.account_id)}"]`);
        if (messageButton && item.latest_message) {
          const message = item.latest_message;
          const body = message.body || `[${message.message_type}]`;
          const sender = [message.sender_name, message.sender_phone].filter(Boolean).join(' · ')
            || message.sender_jid || 'WhatsApp';
          messageButton.querySelector('strong').textContent = body;
          messageButton.querySelector('small').textContent = `${sender} · ${formatLocalTime(message.received_at)}`;
          messageButton.dataset.copyValue = body;
          messageButton.disabled = false;
        } else if (messageButton) {
          messageButton.querySelector('strong').textContent = 'Пока нет сообщений';
          messageButton.querySelector('small').textContent = '';
          delete messageButton.dataset.copyValue;
          messageButton.disabled = true;
        }
      }
    } catch (_) {}
  }

  document.addEventListener('input', (event) => {
    if (event.target.closest('form')) formDirty = true;
  });
  if (document.body.dataset.autoRefresh === 'true') {
    setInterval(() => {
      const editing = document.activeElement?.matches('input, textarea, select');
      const creating = document.querySelector('#create-account-panel')?.open;
      if (!document.hidden && !formDirty && !editing && !creating) {
        persistOpenPanels();
        window.location.reload();
      }
    }, 5000);
  }
  void refreshAccountSummaries();
  setInterval(refreshAccountSummaries, 5000);

  withoutTotp?.addEventListener('change', syncCreateTotpRequirement);
  createPhone?.addEventListener('input', syncCreateWhatsappLogin);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) return;
    for (const input of document.querySelectorAll('input[type="text"][name="totp_secret"]')) {
      input.type = 'password';
      const toggle = document.querySelector(`[data-secret-toggle="${CSS.escape(input.id)}"]`);
      if (toggle) {
        toggle.textContent = 'Показать';
        toggle.setAttribute('aria-label', 'Показать TOTP-секрет');
      }
    }
    for (const target of document.querySelectorAll('[id^="admin-password-"][data-copy-value]')) {
      const revealButton = document.querySelector(`[data-reveal-credentials="${CSS.escape(target.id.replace('admin-password-', ''))}"]`);
      hideRevealedValue(target.id, revealButton);
    }
  });
  window.addEventListener('pagehide', () => {
    for (const target of document.querySelectorAll('[id^="admin-password-"][data-copy-value]')) {
      hideRevealedValue(target.id, null);
    }
  });
  syncCreateTotpRequirement();
  syncCreateWhatsappLogin();
})();
