document.querySelector('#copy-capability')?.addEventListener('click', async (event) => {
  const value = document.querySelector('#capability-url')?.textContent ?? '';
  await navigator.clipboard.writeText(value);
  event.currentTarget.textContent = 'Скопировано';
});
