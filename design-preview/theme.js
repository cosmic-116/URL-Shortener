/* Apply before paint; preference is local to the demo and does not affect classic. */
(() => {
  let preference = 'system';
  try { preference = localStorage.getItem('snip-demo-theme') || 'system'; } catch (_) {}
  const media = matchMedia('(prefers-color-scheme: dark)');
  const apply = () => {
    const dark = preference === 'dark' || (preference === 'system' && media.matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? '#141915' : '#f5f4ee');
    const toggle = document.getElementById('theme-toggle');
    if (toggle) {
      toggle.setAttribute('aria-pressed', String(dark));
      toggle.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
      toggle.innerHTML = `<span aria-hidden="true">${dark ? '☀' : '☾'}</span><span>${dark ? 'Light' : 'Dark'}</span>`;
    }
  };
  apply();
  document.addEventListener('DOMContentLoaded', apply);
  document.addEventListener('click', event => {
    if (!event.target.closest('#theme-toggle')) return;
    preference = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem('snip-demo-theme', preference); } catch (_) {}
    apply();
  });
  media.addEventListener('change', () => { if (preference === 'system') apply(); });
})();
