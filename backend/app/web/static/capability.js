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

document.querySelector('#copy-capability')?.addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const value = document.querySelector('#capability-url')?.textContent?.trim() ?? '';
  if (!value) return;
  button.textContent = await copyText(value) ? 'Скопировано' : 'Скопируйте ссылку вручную';
  setTimeout(() => { button.textContent = 'Скопировать'; }, 1800);
});
