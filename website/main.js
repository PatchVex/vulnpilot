/* PatchVex — main.js */

/* ─── Nav scroll state ───────────────────────────────────────────────────────── */

(function () {
  const nav = document.getElementById('site-nav');
  if (!nav) return;

  function onScroll() {
    nav.classList.toggle('nav-scrolled', window.scrollY > 8);
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
})();

/* ─── Mobile nav overlay ─────────────────────────────────────────────────────── */

(function () {
  const hamburger = document.querySelector('.nav-hamburger');
  const overlay   = document.getElementById('nav-overlay');
  const closeBtn  = document.querySelector('.nav-overlay-close');
  if (!hamburger || !overlay) return;

  function openMenu() {
    overlay.classList.add('open');
    overlay.setAttribute('aria-hidden', 'false');
    hamburger.setAttribute('aria-expanded', 'true');
    document.body.style.overflow = 'hidden';
    closeBtn && closeBtn.focus();
  }

  function closeMenu() {
    overlay.classList.remove('open');
    overlay.setAttribute('aria-hidden', 'true');
    hamburger.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
    hamburger.focus();
  }

  hamburger.addEventListener('click', openMenu);
  closeBtn && closeBtn.addEventListener('click', closeMenu);

  overlay.querySelectorAll('a').forEach(function (a) {
    a.addEventListener('click', closeMenu);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && overlay.classList.contains('open')) closeMenu();
  });
})();

/* ─── Terminal demo (play button + typewriter) ───────────────────────────────── */

(function () {
  var wrap    = document.getElementById('terminal-demo');
  var playBtn = document.getElementById('terminal-play-btn');
  if (!wrap || !playBtn) return;

  var body  = wrap.querySelector('.terminal-body');
  var lines = Array.prototype.slice.call(body.querySelectorAll(':scope > div'));
  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  playBtn.addEventListener('click', function () {
    playBtn.classList.add('hidden');
    wrap.classList.add('terminal-demo-active');

    if (prefersReduced) {
      lines.forEach(function (l) { l.classList.add('t-visible'); });
      return;
    }

    var cmdLine  = lines[0];
    var cmdText  = cmdLine.innerHTML;
    var cursor   = document.createElement('span');
    cursor.className = 't-cursor';
    cursor.setAttribute('aria-hidden', 'true');

    /* Type the command character by character */
    cmdLine.innerHTML = '';
    cmdLine.classList.add('t-visible');
    cmdLine.appendChild(cursor);

    var i = 0;
    var charDelay = 42;

    function typeChar() {
      if (i < cmdText.length) {
        cursor.insertAdjacentHTML('beforebegin', cmdText[i]);
        i++;
        setTimeout(typeChar, charDelay);
      } else {
        /* Done typing — reveal remaining lines */
        revealLines();
      }
    }

    setTimeout(typeChar, 180);

    function revealLines() {
      var lineDelay = 85;
      lines.slice(1).forEach(function (line, idx) {
        setTimeout(function () {
          line.classList.add('t-visible');
          /* Remove cursor after last line */
          if (idx === lines.length - 2) {
            setTimeout(function () { cursor.remove(); }, 600);
          }
        }, idx * lineDelay);
      });
    }
  });
})();

/* ─── Hero copy button ───────────────────────────────────────────────────────── */

(function () {
  const btn     = document.getElementById('hero-copy-btn');
  const cmdEl   = document.querySelector('.hero-install-cmd');
  if (!btn || !cmdEl) return;

  const iconCopy  = btn.querySelector('.icon-copy');
  const iconCheck = btn.querySelector('.icon-check');
  let   resetTimer;

  btn.addEventListener('click', function () {
    navigator.clipboard.writeText(cmdEl.textContent.trim()).then(function () {
      iconCopy.style.display  = 'none';
      iconCheck.style.display = '';
      btn.setAttribute('aria-label', 'Copied!');
      clearTimeout(resetTimer);
      resetTimer = setTimeout(function () {
        iconCopy.style.display  = '';
        iconCheck.style.display = 'none';
        btn.setAttribute('aria-label', 'Copy install command');
      }, 2000);
    }).catch(function () {
      /* clipboard denied — silently no-op */
    });
  });
})();
