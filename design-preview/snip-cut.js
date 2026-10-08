/* Dependency-free guest celebration shared by classic and the alternate demo. */
(() => {
  let active = null;
  const reduced = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
  window.SnipCut = {
    play(longURL, shortURL) {
      if (reduced() || document.hidden) return Promise.resolve();
      if (active) active();
      return new Promise(resolve => {
        const layer = document.createElement('div');
        layer.className = 'snip-cut-overlay';
        layer.setAttribute('aria-hidden', 'true');
        layer.innerHTML = `<div class="snip-cut-scene"><div class="snip-cut-label">A little less link.</div><div class="snip-cut-ribbon"><div class="snip-cut-half snip-cut-left"><span></span></div><div class="snip-cut-half snip-cut-right"><span></span></div><i class="snip-cut-seam"></i></div><svg class="snip-cut-scissors" viewBox="0 0 340 220" fill="none" aria-hidden="true"><g class="snip-cut-upper"><path d="M74 167L138 115L312 54" stroke="#c7d2c9" stroke-width="16" stroke-linecap="round"/><ellipse cx="48" cy="180" rx="37" ry="26" stroke="#e5f45a" stroke-width="15"/></g><g class="snip-cut-lower"><path d="M74 63L138 115L312 176" stroke="#e7eee5" stroke-width="16" stroke-linecap="round"/><ellipse cx="48" cy="50" rx="37" ry="26" stroke="#e5f45a" stroke-width="15"/></g><circle cx="138" cy="115" r="15" fill="#334438" stroke="#f5f4ee" stroke-width="4"/><path d="M130 115h16" stroke="#f5f4ee" stroke-width="3"/></svg><div class="snip-cut-sparks"><i></i><i></i><i></i><i></i></div><div class="snip-cut-result"><span>Ready to go.</span><strong></strong></div></div>`;
        layer.querySelectorAll('.snip-cut-half span').forEach(span => { span.textContent = String(longURL || 'Your long link'); });
        layer.querySelector('.snip-cut-result strong').textContent = String(shortURL || 'Your short link');
        let timer;
        const finish = () => {
          clearTimeout(timer);
          document.removeEventListener('keydown', onKey);
          document.removeEventListener('visibilitychange', onVisibility);
          layer.remove();
          document.documentElement.classList.remove('snip-cut-playing');
          if (active === finish) active = null;
          resolve();
        };
        const onKey = event => { if (event.key === 'Escape') finish(); };
        const onVisibility = () => { if (document.hidden) finish(); };
        active = finish;
        document.addEventListener('keydown', onKey);
        document.addEventListener('visibilitychange', onVisibility);
        document.documentElement.classList.add('snip-cut-playing');
        document.body.append(layer);
        timer = setTimeout(finish, 1750);
      });
    }
  };
})();
