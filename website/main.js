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

/* ─── FAQ accordion ──────────────────────────────────────────────────────────── */

(function () {
  var items = document.querySelectorAll('.faq-item-new');
  items.forEach(function (item) {
    var btn = item.querySelector('.faq-q-new');
    var ans = item.querySelector('.faq-a-new');
    if (!btn || !ans) return;

    btn.addEventListener('click', function () {
      var open = btn.getAttribute('aria-expanded') === 'true';
      if (open) {
        btn.setAttribute('aria-expanded', 'false');
        ans.hidden = true;
      } else {
        btn.setAttribute('aria-expanded', 'true');
        ans.hidden = false;
      }
    });
  });
})();

/* ─── Scoring calculator ─────────────────────────────────────────────────────── */

(function () {
  var kevBtn    = document.getElementById('calc-kev');
  var epssSlider = document.getElementById('calc-epss');
  var cvssSlider = document.getElementById('calc-cvss');
  var segGroup  = document.getElementById('calc-sev');
  if (!kevBtn || !epssSlider || !cvssSlider || !segGroup) return;

  var epssVal   = document.getElementById('calc-epss-val');
  var cvssVal   = document.getElementById('calc-cvss-val');
  var kevLabel  = document.getElementById('calc-kev-label');
  var scoreEl   = document.getElementById('calc-score');
  var badgeEl   = document.getElementById('calc-badge');
  var breakEl   = document.getElementById('calc-breakdown');
  var floorEl   = document.getElementById('calc-kev-floor');

  var state = { kev: false, epss: 0.05, cvss: 7.5, sev: 0.4 };

  var SEV_LABELS = { '0.0': 'None', '0.1': 'Low', '0.4': 'Medium', '0.75': 'High', '1.0': 'Critical' };

  function compute() {
    var kevPts  = state.kev ? 40 : 0;
    var epssPts = 35 * state.epss;
    var cvssPts = 15 * (Math.min(Math.max(state.cvss, 0), 10) / 10);
    var sevPts  = 10 * state.sev;
    var raw = kevPts + epssPts + cvssPts + sevPts;
    var floored = state.kev ? Math.max(raw, 75) : raw;
    var score = Math.min(Math.round(floored * 100) / 100, 100);
    var floorApplied = state.kev && raw < 75;

    var label, scoreClass, badgeClass;
    if (state.kev || score >= 75) {
      label = 'CRITICAL NOW'; scoreClass = 'score-critical'; badgeClass = 'badge-critical';
    } else if (score >= 50) {
      label = 'HIGH'; scoreClass = 'score-high'; badgeClass = 'badge-high';
    } else if (score >= 25) {
      label = 'MEDIUM'; scoreClass = 'score-medium'; badgeClass = 'badge-medium';
    } else {
      label = 'LOW'; scoreClass = 'score-low'; badgeClass = 'badge-low';
    }

    scoreEl.textContent = score.toFixed(1);
    scoreEl.className = 'calc-score-num ' + scoreClass;

    badgeEl.textContent = label;
    badgeEl.className = 'calc-priority-badge ' + badgeClass;

    floorEl.hidden = !floorApplied;

    breakEl.innerHTML = [
      row('KEV match', kevPts.toFixed(1), kevPts > 0),
      row('EPSS × 35', epssPts.toFixed(1), epssPts > 0),
      row('CVSS × 1.5', cvssPts.toFixed(1), cvssPts > 0),
      row('Severity × 10', sevPts.toFixed(1), sevPts > 0),
    ].join('');
  }

  function row(name, val, active) {
    return '<div class="calc-breakdown-row">' +
      '<span class="calc-breakdown-name">' + name + '</span>' +
      '<span class="calc-breakdown-val' + (active ? ' is-active' : '') + '">+' + val + '</span>' +
      '</div>';
  }

  kevBtn.addEventListener('click', function () {
    state.kev = !state.kev;
    kevBtn.setAttribute('aria-checked', String(state.kev));
    kevLabel.textContent = state.kev ? kevBtn.dataset.on : kevBtn.dataset.off;
    compute();
  });

  epssSlider.addEventListener('input', function () {
    state.epss = parseFloat(this.value);
    epssVal.textContent = state.epss.toFixed(2);
    compute();
  });

  cvssSlider.addEventListener('input', function () {
    state.cvss = parseFloat(this.value);
    cvssVal.textContent = state.cvss.toFixed(1);
    compute();
  });

  segGroup.querySelectorAll('.calc-seg-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      segGroup.querySelectorAll('.calc-seg-btn').forEach(function (b) {
        b.classList.remove('active');
        b.setAttribute('aria-checked', 'false');
      });
      btn.classList.add('active');
      btn.setAttribute('aria-checked', 'true');
      state.sev = parseFloat(btn.dataset.val);
      compute();
    });
  });

  compute();
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
