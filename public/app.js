// Theme toggle
(function() {
  var saved = localStorage.getItem('theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);

  var btn = document.getElementById('theme-toggle');
  if (btn) {
    btn.addEventListener('click', function() {
      var current = document.documentElement.getAttribute('data-theme') || 'dark';
      var next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
    });
  }
})();

// Mobile nav toggle
(function() {
  var navToggle = document.getElementById('nav-toggle-btn');
  var navTabs = document.getElementById('nav-tabs');
  if (navToggle && navTabs) {
    navToggle.addEventListener('click', function() {
      var isOpen = navTabs.classList.toggle('open');
      navToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      navToggle.setAttribute('aria-label', isOpen ? 'Close navigation menu' : 'Open navigation menu');
    });
  }
})();

// User menu dropdown
(function() {
  var btn = document.getElementById('user-menu-btn');
  var dropdown = document.getElementById('user-dropdown');
  if (!btn || !dropdown) return;
  btn.addEventListener('click', function(e) {
    e.stopPropagation();
    var open = dropdown.classList.toggle('open');
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  });
  document.addEventListener('click', function(e) {
    if (!btn.contains(e.target) && !dropdown.contains(e.target)) {
      dropdown.classList.remove('open');
      btn.setAttribute('aria-expanded', 'false');
    }
  });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') { dropdown.classList.remove('open'); btn.setAttribute('aria-expanded', 'false'); }
  });
})();

// Sidebar mobile backdrop
(function() {
  var sb = document.getElementById('sidebar');
  var mobileBtn = document.getElementById('sb-mobile-btn');
  if (!sb || !mobileBtn) return;
  var backdrop = document.createElement('div');
  backdrop.className = 'sidebar-backdrop';
  document.body.appendChild(backdrop);
  mobileBtn.addEventListener('click', function() {
    var open = sb.classList.toggle('sb-mobile-open');
    backdrop.classList.toggle('open', open);
  });
  backdrop.addEventListener('click', function() {
    sb.classList.remove('sb-mobile-open');
    backdrop.classList.remove('open');
  });
})();

// Back-to-top button
(function() {
  var btn = document.getElementById('back-to-top');
  if (!btn) return;
  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  window.addEventListener('scroll', function() {
    btn.hidden = window.scrollY < 400;
  }, { passive: true });
  btn.addEventListener('click', function() {
    if (prefersReduced) {
      window.scrollTo(0, 0);
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  });
})();

// Search suggestions
(function () {
  const input = document.getElementById('hero-search');
  const box = document.getElementById('suggestions');
  if (!input || !box) return;

  let debounce = null;
  let activeIdx = -1;

  input.addEventListener('input', function () {
    clearTimeout(debounce);
    const q = input.value.trim();
    if (q.length < 2) { box.innerHTML = ''; box.classList.remove('open'); return; }
    debounce = setTimeout(function () { fetchSuggestions(q); }, 200);
  });

  input.addEventListener('keydown', function (e) {
    const items = box.querySelectorAll('.suggestion-item');
    if (!items.length) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); activeIdx = Math.min(activeIdx + 1, items.length - 1); highlight(items); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); activeIdx = Math.max(activeIdx - 1, 0); highlight(items); }
    else if (e.key === 'Enter' && activeIdx >= 0) { e.preventDefault(); items[activeIdx].click(); }
  });

  document.addEventListener('click', function (e) {
    if (!e.target.closest('.search-box')) { box.innerHTML = ''; box.classList.remove('open'); activeIdx = -1; }
  });

  // Focus search with "/" key
  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
      e.preventDefault();
      input.focus();
    }
  });

  function fetchSuggestions(q) {
    box.innerHTML = '<div class="suggestion-loading"><span class="suggestion-spinner"></span></div>';
    box.classList.add('open');
    fetch('/api/suggest?q=' + encodeURIComponent(q))
      .then(function (r) { return r.json(); })
      .then(function (data) { render(data, q); })
      .catch(function () { box.innerHTML = ''; box.classList.remove('open'); });
  }

  function render(items, q) {
    activeIdx = -1;
    if (!items.length) {
      box.innerHTML = '<div class="suggestion-empty">No results for "' + escHtml(q) + '"</div>';
      box.classList.add('open');
      return;
    }
    box.innerHTML = items.map(function (item) {
      var badges = '';
      if (item.vendor) badges += '<span class="badge badge-vendor">' + escHtml(item.vendor) + '</span>';
      if (item.category) badges += '<span class="badge badge-category">' + escHtml(item.category) + '</span>';
      return '<a href="' + escAttr(item.link) + '" target="_blank" rel="noopener noreferrer" class="suggestion-item">'
        + '<span class="suggestion-title">' + highlightMatch(item.title, q) + '</span>'
        + '<span class="suggestion-badges">' + badges + '</span>'
        + '</a>';
    }).join('');
    box.classList.add('open');
  }

  function highlight(items) {
    items.forEach(function (el, i) { el.classList.toggle('active', i === activeIdx); });
  }

  function escHtml(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function escAttr(s) { return s.replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }

  function highlightMatch(text, q) {
    var safe = escHtml(text);
    var re = new RegExp('(' + escHtml(q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
    return safe.replace(re, '<mark>$1</mark>');
  }
})();

// YARA Rules — shared fetch+render for threat group, software, campaign pages
window.fetchYaraForEntity = function(terms, opts) {
  // opts: { sectionId, wrapId, badgeId, viewAllId, primaryName }
  var section  = document.getElementById(opts.sectionId);
  var wrap     = document.getElementById(opts.wrapId);
  var badge    = document.getElementById(opts.badgeId);
  var viewAll  = document.getElementById(opts.viewAllId);
  if (!wrap) return;

  function esc(s) { var d = document.createElement('div'); d.textContent = String(s || ''); return d.innerHTML; }

  wrap.innerHTML = '<div class="yara-loading-state"><div class="yara-spinner"></div>Searching YARA rules\u2026</div>';

  var seen = {};
  var all = [];
  var pending = terms.length;

  terms.forEach(function(term) {
    fetch('/api/yara-rules?q=' + encodeURIComponent(term))
      .then(function(r) { return r.json(); })
      .then(function(data) {
        (data.results || []).forEach(function(r) {
          if (!seen[r.sha256]) { seen[r.sha256] = true; all.push(r); }
        });
      })
      .catch(function() {})
      .finally(function() {
        if (--pending !== 0) return;

        if (!all.length) {
          wrap.innerHTML = '<p class="empty">No YARA rules found. <a href="/yara-rules?q=' + encodeURIComponent(opts.primaryName) + '" class="yara-more-link" style="display:inline;margin-top:0">Try searching manually \u2192</a></p>';
          return;
        }

        if (section) section.classList.remove('hidden');
        if (badge) { badge.textContent = all.length + ' sample' + (all.length !== 1 ? 's' : ''); badge.removeAttribute('hidden'); }
        if (viewAll) { viewAll.href = '/yara-rules?q=' + encodeURIComponent(opts.primaryName); viewAll.removeAttribute('hidden'); }

        var html = '';
        all.slice(0, 3).forEach(function(s) {
          html += '<div class="yara-sample-card">';
          html += '<div class="yara-card-header">';
          html += '<strong class="yara-card-sig">' + esc(s.signature || s.sha256) + '</strong>';
          if (s.first_seen) html += '<span class="yara-card-date">' + esc(s.first_seen) + '</span>';
          html += '</div>';
          html += '<div class="yara-card-hash">' + esc(s.sha256) + '</div>';
          if (s.tags && s.tags.length) {
            html += '<div>';
            s.tags.slice(0, 6).forEach(function(t) { html += '<span class="ioc-tag">' + esc(t) + '</span> '; });
            html += '</div>';
          }
          if (s.yara_rules && s.yara_rules.length) {
            html += '<div class="yara-rules-summary">';
            html += s.yara_rules.length + ' YARA rule' + (s.yara_rules.length !== 1 ? 's' : '') + ': ';
            html += s.yara_rules.slice(0, 3).map(function(yr) { return '<code class="yara-rule-code">' + esc(yr.name) + '</code>'; }).join(', ');
            if (s.yara_rules.length > 3) html += ' +' + (s.yara_rules.length - 3) + ' more';
            html += '</div>';
          }
          html += '</div>';
        });
        if (all.length > 3) {
          html += '<a href="/yara-rules?q=' + encodeURIComponent(opts.primaryName) + '" class="yara-more-link">View all ' + all.length + ' results on YARA Rules page \u2192</a>';
        }
        wrap.innerHTML = html;
      });
  });
};

// AI Intelligence Brief — shared across threatgroup, software, campaign pages
window.fetchAiBrief = function(type, id) {
  var card = document.getElementById('ai-brief-card');
  var badge = document.getElementById('ai-brief-badge');
  if (!card) return;

  function esc(s) { var d = document.createElement('div'); d.textContent = String(s || ''); return d.innerHTML; }

  card.innerHTML = '<div class="ai-brief-prompt"><span style="font-size:.82rem;color:var(--text-muted)">Generating intelligence brief…</span></div>';

  fetch('/api/ai-context/' + encodeURIComponent(type) + '/' + encodeURIComponent(id))
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) {
        card.innerHTML = '<div style="font-size:.82rem;color:var(--text-muted);padding:.5rem 0">' + esc(data.error) + '</div>';
        return;
      }

      if (badge) { badge.textContent = data.cached ? 'cached' : 'live'; badge.classList.remove('hidden'); }

      var sections = data.sections || [];
      if (!sections.length) {
        // Flat object response (Ollama/Groq)
        sections = Object.entries(data)
          .filter(function(e) { return e[0] !== 'cached' && e[0] !== 'generated_at' && e[1]; })
          .map(function(e) {
            var label = e[0].replace(/_/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });
            var val = Array.isArray(e[1]) ? e[1] : [e[1]];
            return { label: label, items: val };
          });
      }

      var html = '<div class="ai-brief-sections">';
      sections.forEach(function(s) {
        html += '<div class="ai-brief-section">';
        html += '<div class="ai-brief-section-label">' + esc(s.label) + '</div>';
        if (Array.isArray(s.items)) {
          if (s.items.length === 1) {
            html += '<p class="ai-brief-text">' + esc(s.items[0]) + '</p>';
          } else {
            html += '<ul class="ai-brief-list">';
            s.items.forEach(function(item) { html += '<li>' + esc(item) + '</li>'; });
            html += '</ul>';
          }
        } else {
          html += '<p class="ai-brief-text">' + esc(s.items) + '</p>';
        }
        html += '</div>';
      });
      html += '</div>';

      if (data.generated_at) {
        html += '<div class="ai-brief-footer">Generated ' + esc(new Date(data.generated_at).toLocaleString()) + (data.cached ? ' · cached' : '') + '</div>';
      }

      card.innerHTML = html;
    })
    .catch(function() {
      card.innerHTML = '<div style="font-size:.82rem;color:var(--text-muted);padding:.5rem 0">Failed to load AI brief. Check your network connection.</div>';
    });
};

// ── IOC Defanging + Copy ────────────────────────────────────────────────────
// Renders dangerous-looking IOCs in a safe-to-copy form so analysts don't
// accidentally click or auto-execute them. Toggle controlled by:
//   localStorage.iocDefang = "1" | "0"   (default: "1")
// Page-level toggle button: data-toggle="ioc-defang"
// Per-IOC copy buttons:    data-copy-raw="..." or data-copy-defanged="..."
(function() {
  var DEFANG_KEY = 'iocDefang';
  function isDefangOn() { return localStorage.getItem(DEFANG_KEY) !== '0'; }

  // Defang a string. Handles IPs, domains, URLs, emails. Idempotent for already-defanged input.
  function defang(s) {
    if (!s) return s;
    var out = String(s);
    // Already-defanged short-circuit
    if (/\[\.\]|\[:\]|hxxp/i.test(out)) return out;
    // URL scheme: http→hxxp, https→hxxps, ftp→fxp
    out = out.replace(/\bhttps?:\/\//gi, function(m) {
      return m.toLowerCase() === 'https://' ? 'hxxps[:]//' : 'hxxp[:]//';
    });
    out = out.replace(/\bftp:\/\//gi, 'fxp[:]//');
    // Email: user@host → user[@]host
    out = out.replace(/([\w.+-]+)@([\w-]+\.[\w.-]+)/g, '$1[@]$2');
    // Dots inside hostnames/IPs only (not in already-bracketed [.])
    // Strategy: walk tokens and only defang dots inside things that look like IPv4/host
    out = out.replace(/(\b(?:\d{1,3}\.){3}\d{1,3}\b)/g, function(ip) {
      return ip.replace(/\./g, '[.]');
    });
    // Hostnames: any sequence of letters/digits/hyphens with dots between
    out = out.replace(/\b([a-z0-9-]+(?:\.[a-z0-9-]+){1,})\b/gi, function(h) {
      // Skip if it's already defanged or contains scheme/path
      if (h.indexOf('[.]') !== -1 || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return h;
      return h.replace(/\./g, '[.]');
    });
    return out;
  }

  // Apply defanging to every [data-ioc] element on the page based on current setting.
  function applyDefang() {
    var on = isDefangOn();
    document.querySelectorAll('[data-ioc]').forEach(function(el) {
      var raw = el.getAttribute('data-ioc-raw');
      if (!raw) {
        // First call: stash the raw value
        raw = el.textContent.trim();
        el.setAttribute('data-ioc-raw', raw);
      }
      el.textContent = on ? defang(raw) : raw;
      el.classList.toggle('ioc-defanged', on);
    });
    // Update toggle buttons
    document.querySelectorAll('[data-toggle="ioc-defang"]').forEach(function(btn) {
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      var label = btn.querySelector('[data-defang-label]');
      if (label) label.textContent = on ? 'Defanged' : 'Raw';
    });
  }

  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    // Fallback for older browsers
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } finally { document.body.removeChild(ta); }
    return Promise.resolve();
  }

  function flashCopied(btn) {
    var original = btn.getAttribute('data-original-label') || btn.textContent;
    btn.setAttribute('data-original-label', original);
    btn.textContent = 'Copied ✓';
    btn.classList.add('copied');
    setTimeout(function() {
      btn.textContent = original;
      btn.classList.remove('copied');
    }, 1200);
  }

  document.addEventListener('click', function(e) {
    var t = e.target.closest('[data-toggle="ioc-defang"]');
    if (t) {
      e.preventDefault();
      var next = isDefangOn() ? '0' : '1';
      localStorage.setItem(DEFANG_KEY, next);
      applyDefang();
      return;
    }
    var copyRaw = e.target.closest('[data-copy-raw]');
    if (copyRaw) {
      e.preventDefault();
      copyToClipboard(copyRaw.getAttribute('data-copy-raw'));
      flashCopied(copyRaw);
      return;
    }
    var copyDef = e.target.closest('[data-copy-defanged]');
    if (copyDef) {
      e.preventDefault();
      copyToClipboard(defang(copyDef.getAttribute('data-copy-defanged')));
      flashCopied(copyDef);
      return;
    }
    var copyAll = e.target.closest('[data-copy-all-iocs]');
    if (copyAll) {
      e.preventDefault();
      var items = Array.from(document.querySelectorAll('[data-ioc]'))
        .map(function(el) { return el.getAttribute('data-ioc-raw') || el.textContent.trim(); });
      var text = isDefangOn() ? items.map(defang).join('\n') : items.join('\n');
      copyToClipboard(text);
      flashCopied(copyAll);
    }
  });

  // Apply on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyDefang);
  } else {
    applyDefang();
  }

  // Expose for inline use (lookup pages, etc.)
  window.iocDefang = { defang: defang, apply: applyDefang, isOn: isDefangOn };
})();

// ── Command Palette (Cmd/Ctrl-K) + Shortcut Sheet (?) ───────────────────────
// Lazy: nothing renders until first invocation. The list of static destinations
// is local; entity search hits /api/suggest which is already implemented.
(function() {
  var STATIC_NAV = [
    { label: 'Threat Feed',          href: '/feed',         hint: 'main feed' },
    { label: 'IOC Feed',             href: '/iocs',         hint: 'extracted indicators' },
    { label: 'Geomap',               href: '/geomap',       hint: 'threat actor / IOC map' },
    { label: 'Threat Groups',        href: '/threat-groups',hint: 'APTs & adversaries' },
    { label: 'Software / Malware',   href: '/software' },
    { label: 'Campaigns',            href: '/campaigns' },
    { label: 'Cases',                href: '/cases' },
    { label: 'CVEs (priority)',      href: '/cvepriority' },
    { label: 'MITRE ATT&CK',         href: '/mitre' },
    { label: 'Heatmap',              href: '/heatmap' },
    { label: 'YARA Rules',           href: '/yara' },
    { label: 'SSL Blacklist',        href: '/sslblacklist' },
    { label: 'Watchlist',            href: '/watchlist' },
    { label: 'Pastes',               href: '/pastes' },
    { label: 'Dark Web',             href: '/darkweb' },
    { label: 'Alerts',               href: '/alerts',       hint: 'subscribe / rules' },
    { label: 'API Keys',             href: '/api-keys' },
    { label: 'Admin',                href: '/admin' },
    { label: 'Audit Log',            href: '/admin/audit' },
    { label: 'Search…',              href: '/search',       hint: 'full-text search' },
  ];

  var palette = null, input = null, list = null, lastQuery = '', suggestTimer = null;

  function build() {
    if (palette) return;
    palette = document.createElement('div');
    palette.id = 'cmd-palette';
    palette.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:9998;display:none;align-items:flex-start;justify-content:center;padding-top:12vh';
    palette.innerHTML = ''
      + '<div role="dialog" aria-label="Command palette" style="width:min(560px,92vw);background:var(--bg-card);border:1px solid var(--border);border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.5);overflow:hidden">'
      +   '<div style="padding:.75rem .9rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.5rem">'
      +     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="color:var(--text-muted)"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>'
      +     '<input id="cmd-palette-input" type="text" placeholder="Jump to page or search threat groups, malware, campaigns…" autocomplete="off" autocorrect="off" spellcheck="false" style="flex:1;background:transparent;border:0;outline:0;color:var(--text);font-size:.95rem">'
      +     '<kbd style="font-size:.7rem;color:var(--text-muted);border:1px solid var(--border);padding:.1rem .35rem;border-radius:4px">esc</kbd>'
      +   '</div>'
      +   '<div id="cmd-palette-list" style="max-height:55vh;overflow-y:auto;padding:.4rem"></div>'
      +   '<div style="padding:.45rem .75rem;border-top:1px solid var(--border);font-size:.7rem;color:var(--text-muted);display:flex;justify-content:space-between"><span>↑↓ navigate · ↵ open</span><span>?  shortcuts</span></div>'
      + '</div>';
    document.body.appendChild(palette);
    input = palette.querySelector('#cmd-palette-input');
    list = palette.querySelector('#cmd-palette-list');

    palette.addEventListener('click', function(e) { if (e.target === palette) close(); });
    input.addEventListener('input', function() { schedule(input.value); });
    input.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') { e.preventDefault(); close(); return; }
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        moveSel(e.key === 'ArrowDown' ? 1 : -1);
        return;
      }
      if (e.key === 'Enter') {
        e.preventDefault();
        var sel = list.querySelector('.cmd-sel') || list.querySelector('a');
        if (sel) sel.click();
      }
    });
  }

  function open() {
    build();
    palette.style.display = 'flex';
    input.value = '';
    lastQuery = '';
    render([]);
    setTimeout(function() { input.focus(); }, 10);
  }
  function close() { if (palette) palette.style.display = 'none'; }

  function moveSel(delta) {
    var items = Array.from(list.querySelectorAll('a'));
    if (!items.length) return;
    var idx = items.findIndex(function(a) { return a.classList.contains('cmd-sel'); });
    if (idx >= 0) items[idx].classList.remove('cmd-sel');
    idx = (idx + delta + items.length) % items.length;
    items[idx].classList.add('cmd-sel');
    items[idx].scrollIntoView({ block: 'nearest' });
  }

  function render(extras) {
    var q = (lastQuery || '').toLowerCase();
    var nav = STATIC_NAV.filter(function(item) {
      if (!q) return true;
      return item.label.toLowerCase().indexOf(q) !== -1 || (item.hint || '').toLowerCase().indexOf(q) !== -1;
    });
    list.innerHTML = '';

    function addRow(label, href, hint, icon) {
      var a = document.createElement('a');
      a.href = href;
      a.style.cssText = 'display:flex;align-items:center;gap:.6rem;padding:.5rem .65rem;border-radius:8px;color:var(--text);text-decoration:none;font-size:.88rem';
      a.innerHTML = '<span style="font-size:.95rem">' + (icon || '→') + '</span><span style="flex:1">' + label + '</span>' + (hint ? '<span style="font-size:.72rem;color:var(--text-muted)">' + hint + '</span>' : '');
      a.addEventListener('mouseenter', function() {
        list.querySelectorAll('.cmd-sel').forEach(function(x) { x.classList.remove('cmd-sel'); });
        a.classList.add('cmd-sel');
      });
      list.appendChild(a);
    }
    nav.forEach(function(it) { addRow(it.label, it.href, it.hint, '↗'); });
    (extras || []).forEach(function(it) { addRow(it.label, it.href, it.hint || it.type || '', '◆'); });

    if (!list.children.length) {
      list.innerHTML = '<div style="padding:1rem;color:var(--text-muted);font-size:.85rem">No matches.</div>';
    } else {
      // Auto-select first item
      list.querySelector('a').classList.add('cmd-sel');
    }
  }

  function schedule(q) {
    lastQuery = q;
    render([]);
    if (suggestTimer) clearTimeout(suggestTimer);
    if (!q || q.length < 2) return;
    suggestTimer = setTimeout(function() {
      fetch('/api/suggest?q=' + encodeURIComponent(q))
        .then(function(r) { return r.json(); })
        .then(function(items) {
          if (lastQuery !== q) return;
          var extras = (items || []).slice(0, 8).map(function(it) {
            // /api/suggest returns rows with .name and .href set client-side
            // but the existing endpoint already shapes them — be defensive.
            var label = it.label || it.name || it.title || 'unknown';
            var href = it.href || it.url || '/search?q=' + encodeURIComponent(label);
            return { label: label, href: href, type: it.type || 'result' };
          });
          render(extras);
        })
        .catch(function() {});
    }, 200);
  }

  // Shortcut sheet — separate, simpler modal
  var sheet = null;
  function buildSheet() {
    if (sheet) return;
    sheet = document.createElement('div');
    sheet.id = 'shortcut-sheet';
    sheet.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:9998;display:none;align-items:center;justify-content:center';
    sheet.innerHTML = ''
      + '<div role="dialog" aria-label="Keyboard shortcuts" style="width:min(420px,92vw);background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:1.25rem 1.5rem;box-shadow:0 20px 60px rgba(0,0,0,.5)">'
      +   '<h3 style="margin:0 0 .9rem;font-size:1rem">Keyboard shortcuts</h3>'
      +   '<table style="width:100%;border-collapse:collapse;font-size:.85rem"><tbody>'
      +     '<tr><td style="padding:.35rem 0;color:var(--text-muted)">Open command palette</td><td style="text-align:right"><kbd>⌘K</kbd> / <kbd>Ctrl K</kbd></td></tr>'
      +     '<tr><td style="padding:.35rem 0;color:var(--text-muted)">Focus search</td><td style="text-align:right"><kbd>/</kbd></td></tr>'
      +     '<tr><td style="padding:.35rem 0;color:var(--text-muted)">Show shortcuts</td><td style="text-align:right"><kbd>?</kbd></td></tr>'
      +     '<tr><td style="padding:.35rem 0;color:var(--text-muted)">Toggle defang on IOC pages</td><td style="text-align:right"><kbd>D</kbd></td></tr>'
      +     '<tr><td style="padding:.35rem 0;color:var(--text-muted)">Close any modal</td><td style="text-align:right"><kbd>Esc</kbd></td></tr>'
      +   '</tbody></table>'
      +   '<div style="margin-top:.8rem;text-align:right"><button type="button" id="shortcut-close" class="btn btn-sm">Close</button></div>'
      + '</div>';
    document.body.appendChild(sheet);
    sheet.addEventListener('click', function(e) { if (e.target === sheet || e.target.id === 'shortcut-close') closeSheet(); });
  }
  function openSheet() { buildSheet(); sheet.style.display = 'flex'; }
  function closeSheet() { if (sheet) sheet.style.display = 'none'; }

  // Global key handler
  document.addEventListener('keydown', function(e) {
    var inField = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target && e.target.tagName) || '') || (e.target && e.target.isContentEditable);
    // Cmd/Ctrl-K opens palette from anywhere
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      open();
      return;
    }
    if (inField) return;
    // ? opens shortcuts (Shift-/ on US keyboards)
    if (e.key === '?') { e.preventDefault(); openSheet(); return; }
    // D toggles defang
    if (e.key.toLowerCase() === 'd' && !e.metaKey && !e.ctrlKey && !e.altKey) {
      var btn = document.querySelector('[data-toggle="ioc-defang"]');
      if (btn) { e.preventDefault(); btn.click(); }
    }
    if (e.key === 'Escape') { close(); closeSheet(); }
  });

  // Selected-item style
  var st = document.createElement('style');
  st.textContent = '#cmd-palette .cmd-sel { background: var(--bg-elevated); }';
  document.head.appendChild(st);

  window.cmdPalette = { open: open, close: close, openShortcuts: openSheet };
})();
