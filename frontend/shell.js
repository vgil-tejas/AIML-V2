/* Shared app chrome for the split-out feature pages. Injects the EXACT neural-
   spine sidebar + topbar used by the SPA (styled by app.css) so every standalone
   page is visually identical to the dashboard. A page just provides:
     <div class="shell" id="shell"><main class="main"><div class="topbar" id="topbar"></div>
        <div class="page active"> …feature content… </div></main></div>
   and sets window.PAGE / window.PAGE_TITLE before loading this file. */
(function () {
  var PAGE = window.PAGE || '';
  var TITLE = window.PAGE_TITLE || '';
  // [key, label, number, accent, href] — split pages go to their .html, the rest
  // hand off to the SPA via the hash router (/#page); Overview is the SPA hub (/).
  var NAV = [
    ['Command', [
      ['overview', 'Overview', '01', '#5e6ad2', '/'],
      ['incidents', 'Incidents', '02', '#eb5757', 'incidents.html'],
    ]],
    ['Detect', [
      ['deviations', 'Deviations', '03', '#eb5757', '/#deviations'],
      ['ueba', 'UEBA · Identity', '04', '#a78bfa', 'ueba.html'],
      ['ml', 'Anomalies · ML', '05', '#a78bfa', '/#ml'],
      ['bslexplorer', 'Baseline Explorer', '06', '#f2c94c', '/#bslexplorer'],
    ]],
    ['Investigate', [
      ['trail', 'IP Trail', '07', '#f2c94c', '/#trail'],
      ['logs', 'Logs Explorer', '08', '#4cb782', 'logs.html'],
      ['aiinvestigate', 'AI Investigator', '09', '#a78bfa', '/#aiinvestigate'],
      ['nlquery', 'SOC Query', '10', '#a78bfa', '/#nlquery'],
    ]],
    ['Intel', [
      ['intelligence', 'Intelligence', '11', '#4cb782', '/#intelligence'],
      ['killchain', 'Kill Chain', '12', '#a78bfa', '/#killchain'],
    ]],
    ['Operate', [
      ['playbooks', 'Responder', '13', '#5e6ad2', '/#playbooks'],
      ['reports', 'Reports', '14', '#8a8f98', '/#reports'],
    ]],
  ];
  var esc = function (s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'); };

  // key -> {label, href} so the pjax engine can set the title + active state.
  var LABELS = {};
  NAV.forEach(function (grp) { grp[1].forEach(function (it) { LABELS[it[0]] = { label: it[1], href: it[4] }; }); });

  var navHtml = NAV.map(function (grp) {
    var sec = grp[0], items = grp[1];
    return '<div class="ns"><span>' + esc(sec) + '</span></div>' + items.map(function (it) {
      var k = it[0], label = it[1], num = it[2], col = it[3], href = it[4];
      // data-nav/data-href + a delegated handler (below) instead of inline
      // location.href, so navigation can be soft (pjax) and self-clicks no-op.
      return '<div class="ni' + (k === PAGE ? ' active' : '') + '" data-nav="' + esc(k) + '" data-href="' + esc(href) + '" data-label="' + esc(label) + '" title="' + esc(label) +
        '" style="--nc:' + col + '">' +
        '<span class="node"></span><i class="nix">' + num + '</i><span class="nlab">' +
        esc(label).replace('·', '&middot;') + '</span><span class="nbadge"></span></div>';
    }).join('');
  }).join('');

  var RAIL = '<aside class="sidebar rail" id="rail">' +
    '<div class="logo rail-core">' +
      '<img class="brand-logo" src="logo-brand.jpg?v=1" alt="CyberSentinel" />' +
      '<button class="rail-btn" id="rail-btn" onclick="toggleRail()" title="Collapse rail — Ctrl+B" aria-label="Collapse rail">&#10216;</button>' +
    '</div>' +
    '<nav class="nav spine"><span class="spine-trace" aria-hidden="true"><i class="photon"></i></span>' + navHtml + '</nav>' +
  '</aside>';

  var TOPBAR =
    '<div class="nav-arrows">' +
      '<button class="nav-btn" onclick="history.back()" title="Back" aria-label="Back">&#8249;</button>' +
      '<button class="nav-btn" onclick="history.forward()" title="Forward" aria-label="Forward">&#8250;</button>' +
    '</div>' +
    '<h1 id="page-title">' + esc(TITLE) + '</h1>' +
    '<div class="srch">' +
      '<svg width="13" height="13" fill="none" stroke="var(--muted)" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35" stroke-linecap="round"/></svg>' +
      '<input id="ip-search" placeholder="Search IP…" onkeydown="if(event.key===\'Enter\'&&this.value.trim())location.href=\'/#trail=\'+encodeURIComponent(this.value.trim())" />' +
    '</div>' +
    '<span id="shell-op" style="margin-left:auto;font-size:12px;color:var(--muted)"></span>' +
    '<button class="btn" id="shell-logout" style="margin-left:10px">Log out</button>';

  var shell = document.getElementById('shell');
  if (shell) shell.insertAdjacentHTML('afterbegin', RAIL);   // aside becomes grid col 1
  var tb = document.getElementById('topbar');
  if (tb) tb.innerHTML = TOPBAR;

  // Rail collapse — identical behaviour to the SPA (body.rail-min, Ctrl+B, persisted).
  window.toggleRail = function () {
    var min = document.body.classList.toggle('rail-min');
    try { localStorage.setItem('cs_rail_min', min ? '1' : '0'); } catch (e) {}
    var b = document.getElementById('rail-btn');
    if (b) { b.innerHTML = min ? '&#10217;' : '&#10216;'; b.title = (min ? 'Expand' : 'Collapse') + ' rail — Ctrl+B'; }
  };
  try { if (localStorage.getItem('cs_rail_min') === '1') { document.body.classList.add('rail-min'); var b = document.getElementById('rail-btn'); if (b) b.innerHTML = '&#10217;'; } } catch (e) {}
  document.addEventListener('keydown', function (e) { if (e.ctrlKey && (e.key === 'b' || e.key === 'B')) { e.preventDefault(); window.toggleRail(); } });

  // ── Soft navigation (pjax) ─────────────────────────────────────────────────
  // The shell is mounted once. Hopping between the split pages swaps only the
  // .page content (no document reload, no flash); clicking the page you're on
  // does nothing; anything into the SPA is a normal nav that View Transitions
  // crossfade. Each split page's code script is an IIFE marked data-page, so it
  // re-runs cleanly on every swap without redeclaring globals.
  var SPLIT = { 'incidents.html': 'incidents', 'ueba.html': 'ueba', 'logs.html': 'logs' };
  function curFile() { var p = location.pathname.split('/').pop(); return p || 'index.html'; }
  function setActive(page) {
    var items = document.querySelectorAll('.ni');
    for (var i = 0; i < items.length; i++) items[i].classList.toggle('active', items[i].getAttribute('data-nav') === page);
  }
  function injectPjaxStyles(doc) {
    var old = document.querySelectorAll('style[data-pjax-style]');
    for (var i = 0; i < old.length; i++) old[i].remove();
    var styles = doc.querySelectorAll('head style');
    for (var j = 0; j < styles.length; j++) { var c = styles[j].cloneNode(true); c.setAttribute('data-pjax-style', '1'); document.head.appendChild(c); }
  }
  function runPageScript(doc) {
    var old = document.querySelectorAll('[data-pjax-script]');
    for (var i = 0; i < old.length; i++) old[i].remove();
    var src = doc.querySelector('script[data-page]');
    if (!src) return;
    var s = document.createElement('script');
    s.textContent = src.textContent;
    s.setAttribute('data-pjax-script', '1');
    document.body.appendChild(s);
  }
  var _pjaxBusy = false;
  function pjaxGo(href, page, push) {
    if (_pjaxBusy) return; _pjaxBusy = true;
    fetch(href, { credentials: 'same-origin' }).then(function (r) { if (!r.ok) throw 0; return r.text(); })
      .then(function (html) {
        var doc = new DOMParser().parseFromString(html, 'text/html');
        var newPage = doc.querySelector('main.main > .page') || doc.querySelector('.page');
        var curPage = document.querySelector('main.main > .page');
        if (!newPage || !curPage) { location.href = href; return; }
        var apply = function () {
          injectPjaxStyles(doc);
          curPage.replaceWith(newPage);
          document.title = doc.title || document.title;
          var h1 = document.getElementById('page-title');
          if (h1 && LABELS[page]) h1.textContent = LABELS[page].label.replace('·', '·');
          setActive(page); window.PAGE = page;
          runPageScript(doc);
          var m = document.querySelector('main.main'); if (m) m.scrollTop = 0;
        };
        if (document.startViewTransition) document.startViewTransition(apply); else apply();
        if (push !== false) history.pushState({ pjax: 1, href: href, page: page }, '', href);
      })
      .catch(function () { location.href = href; })      // any failure -> honest full navigation
      .finally(function () { _pjaxBusy = false; });
  }
  function navTo(href, page) {
    if (!href) return;
    var cur = curFile();
    if (href === cur || (page && page === window.PAGE)) return;   // self-click: no reload
    if (SPLIT[href]) { pjaxGo(href, SPLIT[href], true); return; } // soft swap between split pages
    location.href = href;                                         // boundary -> full nav (crossfaded)
  }
  var railEl = document.getElementById('rail');
  if (railEl) railEl.addEventListener('click', function (e) {
    var ni = e.target.closest ? e.target.closest('.ni') : null;
    if (ni) navTo(ni.getAttribute('data-href'), ni.getAttribute('data-nav'));
  });
  window.addEventListener('popstate', function () {
    var f = curFile();
    if (SPLIT[f]) pjaxGo(f, SPLIT[f], false);   // back/forward among split pages: re-render in place
  });

  var lo = document.getElementById('shell-logout');
  if (lo) lo.onclick = function () { fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }).catch(function () {}).then(function () { location.replace('/login.html'); }); };

  fetch('/api/auth/me', { credentials: 'same-origin' }).then(function (r) { return r.ok ? r.json() : null; })
    .then(function (r) { if (r && r.user) { var o = document.getElementById('shell-op'); if (o) o.textContent = 'operator: ' + r.user; } }).catch(function () {});
  fetch('/api/health', { credentials: 'same-origin' }).then(function (r) {
    var dot = document.getElementById('rh-dot'), txt = document.getElementById('rh-txt'), ok = r.ok;
    if (dot) dot.style.background = ok ? 'var(--ok)' : 'var(--danger)';
    if (txt) txt.textContent = ok ? 'pipeline online' : 'degraded';
  }).catch(function () { var txt = document.getElementById('rh-txt'); if (txt) txt.textContent = 'offline'; });
})();
