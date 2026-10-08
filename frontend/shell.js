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

  var navHtml = NAV.map(function (grp) {
    var sec = grp[0], items = grp[1];
    return '<div class="ns"><span>' + esc(sec) + '</span></div>' + items.map(function (it) {
      var k = it[0], label = it[1], num = it[2], col = it[3], href = it[4];
      return '<div class="ni' + (k === PAGE ? ' active' : '') + '" data-label="' + esc(label) + '" title="' + esc(label) +
        '" onclick="location.href=\'' + href + '\'" style="--nc:' + col + '">' +
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
