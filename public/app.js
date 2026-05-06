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
