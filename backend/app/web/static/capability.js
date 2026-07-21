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

document.querySelector('#copy-capability')?.addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const value = document.querySelector('#capability-url')?.textContent?.trim() ?? '';
  if (!value) return;
  button.textContent = await copyText(value) ? 'Скопировано' : 'Скопируйте ссылку вручную';
  setTimeout(() => { button.textContent = 'Скопировать'; }, 1800);
});
