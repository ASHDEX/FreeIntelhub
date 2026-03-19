// Theme toggle
(function() {
  var saved = localStorage.getItem('theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);

  var btn = document.getElementById('theme-toggle');
  if (btn) {
    var initTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    btn.setAttribute('aria-pressed', initTheme === 'light' ? 'true' : 'false');
    btn.addEventListener('click', function() {
      var current = document.documentElement.getAttribute('data-theme') || 'dark';
      var next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
      btn.setAttribute('aria-pressed', next === 'light' ? 'true' : 'false');
    });
  }
})();

(function() {
  var sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  // Close sidebar on mobile nav item click
  document.querySelectorAll('.sb-item').forEach(function(a) {
    a.addEventListener('click', function() {
      if (window.innerWidth <= 768) {
        sidebar.classList.remove('sb-mobile-open');
      }
    });
  });
  // Keyboard shortcut: / focuses topbar search
  document.addEventListener('keydown', function(e) {
    if (e.key === '/' && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)) {
      e.preventDefault();
      var inp = document.querySelector('.topbar-search input');
      if (inp) inp.focus();
    }
  });
})();

// Search suggestions — shared helpers + wires up both hero and topbar inputs
(function () {
  // ── Shared helpers ───────────────────────────────────────────────────────────
  function escHtml(s) { var d = document.createElement('div'); d.textContent = String(s || ''); return d.innerHTML; }
  function escAttr(s) { return String(s || '').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
  function highlightMatch(text, q) {
    var safe = escHtml(text);
    var re = new RegExp('(' + escHtml(q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
    return safe.replace(re, '<mark>$1</mark>');
  }

  var TYPE_META = {
    'article':      { label: 'Article',      icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>', cls: 'badge-source' },
    'threat-group': { label: 'Threat Actor', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>', cls: 'badge-mitre' },
    'software':     { label: 'Malware',       icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>', cls: 'badge-category' },
    'campaign':     { label: 'Campaign',      icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>', cls: 'badge-vendor' },
    'yara':         { label: 'YARA Rules',    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>', cls: 'badge-yara' },
  };

  function renderItems(box, items, q) {
    var activeIdx = 0;
    if (!items.length) {
      box.innerHTML = '<div class="suggestion-empty">No results for "' + escHtml(q) + '"</div>';
      box.classList.add('open');
      return;
    }

    // Group entities vs articles
    var entityTypes = ['threat-group', 'software', 'campaign'];
    var entities = items.filter(function(i) { return entityTypes.includes(i.type); });
    var articles = items.filter(function(i) { return i.type === 'article'; });
    var yara = items.filter(function(i) { return i.type === 'yara'; });

    var html = '';

    if (entities.length) {
      html += '<div class="suggest-section-label">Entities</div>';
      entities.forEach(function(item) {
        var m = TYPE_META[item.type] || TYPE_META['article'];
        html += '<a href="' + escAttr(item.link) + '" class="suggestion-item">'
          + '<span class="suggest-icon">' + m.icon + '</span>'
          + '<span class="suggestion-title">' + highlightMatch(item.title, q) + '</span>'
          + '<span class="suggestion-badges"><span class="badge ' + m.cls + '">' + m.label + '</span></span>'
          + '</a>';
      });
    }

    if (yara.length) {
      html += '<div class="suggest-section-label">Detection Rules</div>';
      yara.forEach(function(item) {
        var m = TYPE_META['yara'];
        html += '<a href="' + escAttr(item.link) + '" class="suggestion-item suggest-yara-item">'
          + '<span class="suggest-icon">' + m.icon + '</span>'
          + '<span class="suggestion-title">Search YARA rules for <strong>' + escHtml(item.title) + '</strong></span>'
          + '<span class="suggestion-badges"><span class="badge badge-yara">YARA</span></span>'
          + '</a>';
      });
    }

    if (articles.length) {
      html += '<div class="suggest-section-label">Articles</div>';
      articles.forEach(function(item) {
        var badges = '';
        if (item.vendor) badges += '<span class="badge badge-vendor">' + escHtml(item.vendor) + '</span>';
        if (item.category) badges += '<span class="badge badge-category">' + escHtml(item.category) + '</span>';
        html += '<a href="' + escAttr(item.link) + '" target="_blank" rel="noopener noreferrer" class="suggestion-item">'
          + '<span class="suggest-icon">' + TYPE_META['article'].icon + '</span>'
          + '<span class="suggestion-title">' + highlightMatch(item.title, q) + '</span>'
          + '<span class="suggestion-badges">' + badges + '</span>'
          + '</a>';
      });
    }

    box.innerHTML = html;
    box.classList.add('open');
  }

  function attachSuggestions(inputEl, boxEl, closeSelector) {
    if (!inputEl || !boxEl) return;
    var debounce = null;
    var activeIdx = -1;

    inputEl.addEventListener('input', function () {
      clearTimeout(debounce);
      var q = inputEl.value.trim();
      if (q.length < 2) { boxEl.innerHTML = ''; boxEl.classList.remove('open'); return; }
      debounce = setTimeout(function () {
        boxEl.innerHTML = '<div class="suggestion-loading"><span class="suggestion-spinner"></span></div>';
        boxEl.classList.add('open');
        fetch('/api/suggest?q=' + encodeURIComponent(q))
          .then(function (r) { return r.json(); })
          .then(function (data) { renderItems(boxEl, data, q); })
          .catch(function () { boxEl.innerHTML = ''; boxEl.classList.remove('open'); });
      }, 220);
    });

    inputEl.addEventListener('keydown', function (e) {
      var items = boxEl.querySelectorAll('.suggestion-item');
      if (!items.length) return;
      if (e.key === 'ArrowDown') { e.preventDefault(); activeIdx = Math.min(activeIdx + 1, items.length - 1); items.forEach(function(el, i) { el.classList.toggle('active', i === activeIdx); }); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); activeIdx = Math.max(activeIdx - 1, 0); items.forEach(function(el, i) { el.classList.toggle('active', i === activeIdx); }); }
      else if (e.key === 'Enter' && activeIdx >= 0) { e.preventDefault(); items[activeIdx].click(); }
      else if (e.key === 'Escape') { boxEl.innerHTML = ''; boxEl.classList.remove('open'); activeIdx = -1; }
    });

    document.addEventListener('click', function (e) {
      if (!e.target.closest(closeSelector)) { boxEl.innerHTML = ''; boxEl.classList.remove('open'); activeIdx = -1; }
    });
  }

  // Hero search (homepage)
  attachSuggestions(
    document.getElementById('hero-search'),
    document.getElementById('suggestions'),
    '.search-box'
  );

  // Topbar search (all pages)
  attachSuggestions(
    document.getElementById('topbar-search-input'),
    document.getElementById('topbar-suggestions'),
    '.topbar-search-wrap'
  );
})();

// Case management — "Add to Case" dropdown
(function() {
  var openDrop = null;

  function closeAllDrops() {
    document.querySelectorAll('.case-dropdown').forEach(function(d) { d.style.display = 'none'; });
    openDrop = null;
  }

  document.addEventListener('click', function(e) {
    var btn = e.target.closest('.case-add-btn');
    if (btn) {
      e.stopPropagation();
      var articleId = btn.dataset.article;
      var drop = document.getElementById('case-drop-' + articleId);
      if (!drop) return;
      if (drop.style.display !== 'none') { closeAllDrops(); return; }
      closeAllDrops();
      renderCaseDropdown(drop, articleId);
      drop.style.display = 'block';
      openDrop = drop;
      return;
    }
    if (!e.target.closest('.case-dropdown')) closeAllDrops();
  });

  function renderCaseDropdown(drop, articleId) {
    drop.innerHTML = '<div class="case-dropdown-item" style="color:var(--text-muted);font-size:.75rem;pointer-events:none">Loading cases...</div>';
    fetch('/api/cases').then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }).then(function(cases) {
      if (!cases.length) {
        drop.innerHTML = '<div class="case-dropdown-item" style="color:var(--text-muted);pointer-events:none">No open cases. <a href="/cases" style="color:var(--accent)">Create one</a></div>';
        return;
      }
      var sevIcons = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
      drop.innerHTML = cases.map(function(c) {
        var col = sevIcons[c.severity] || '#64748b';
        return '<div class="case-dropdown-item" data-case="' + c.id + '" data-article="' + articleId + '">'
          + '<span style="width:8px;height:8px;border-radius:50%;background:' + col + ';flex-shrink:0"></span>'
          + '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escHtml(c.title) + '</span>'
          + '</div>';
      }).join('')
      + '<div style="border-top:1px solid var(--border);margin:.3rem 0"></div>'
      + '<a href="/cases" class="case-dropdown-item" style="color:var(--accent);text-decoration:none">'
      + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>'
      + 'Manage Cases</a>';
    }).catch(function() {
      drop.innerHTML = '<div class="case-dropdown-item" style="color:var(--text-muted);pointer-events:none">Error loading cases</div>';
    });
  }

  document.addEventListener('click', function(e) {
    var item = e.target.closest('.case-dropdown-item[data-case]');
    if (!item) return;
    var caseId = item.dataset.case;
    var articleId = item.dataset.article;
    fetch('/api/cases/' + caseId + '/articles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ article_id: articleId })
    }).then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }).then(function(d) {
      if (d.ok) {
        item.innerHTML = '<span style="color:#22c55e">&#10003;</span> <span>Added!</span>';
        setTimeout(closeAllDrops, 800);
      }
    });
  });

  function escHtml(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
})();

// Analyst Notes
(function() {
  var TOKEN_KEY = 'fih_subscriber_token';

  function getToken() { return localStorage.getItem(TOKEN_KEY) || ''; }

  document.addEventListener('click', function(e) {
    var btn = e.target.closest('.note-toggle-btn');
    if (btn) {
      var articleId = btn.dataset.article;
      var panel = document.getElementById('note-panel-' + articleId);
      if (!panel) return;
      var wasHidden = panel.style.display === 'none';
      panel.style.display = wasHidden ? 'block' : 'none';
      if (wasHidden) loadNotes(articleId);
    }

    var saveBtn = e.target.closest('.note-save-btn');
    if (saveBtn) {
      var articleId = saveBtn.dataset.article;
      var panel = document.getElementById('note-panel-' + articleId);
      if (!panel) return;
      var noteText = panel.querySelector('.note-text-inp').value.trim();
      var tag = panel.querySelector('.note-tag-sel').value;
      var token = getToken();
      if (!token) {
        token = prompt('Enter your subscriber token (from the Alerts page):');
        if (token) localStorage.setItem(TOKEN_KEY, token);
      }
      if (!token || !noteText) return;
      fetch('/api/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ article_id: articleId, token: token, note: noteText, tag: tag })
      }).then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }).then(function(d) {
        if (d.ok) {
          panel.querySelector('.note-text-inp').value = '';
          loadNotes(articleId);
        }
      });
    }
  });

  function loadNotes(articleId) {
    var list = document.getElementById('note-list-' + articleId);
    if (!list) return;
    fetch('/api/notes/' + articleId).then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }).then(function(d) {
      if (!d.notes || d.notes.length === 0) {
        list.innerHTML = '<p style="font-size:.75rem;color:var(--text-muted);margin:.4rem 0">No notes yet.</p>';
        return;
      }
      var tagColors = { confirmed: '#22c55e', 'false-positive': '#ef4444', 'under-investigation': '#fbbf24', archived: '#94a3b8', note: '#22d3ee' };
      function escN(s) { var d = document.createElement('div'); d.textContent = String(s || ''); return d.innerHTML; }
      list.innerHTML = d.notes.map(function(n) {
        var col = tagColors[escN(n.tag)] || '#22d3ee';
        return '<div style="display:flex;gap:.4rem;align-items:flex-start;padding:.35rem 0;border-top:1px solid var(--border)">'
          + '<span style="font-size:.7rem;padding:.15rem .4rem;border-radius:4px;background:rgba(0,0,0,.2);border:1px solid ' + col + ';color:' + col + ';flex-shrink:0">' + escN(n.tag) + '</span>'
          + '<span style="font-size:.78rem;color:var(--text-secondary);flex:1">' + escN(n.note) + '</span>'
          + '<span style="font-size:.7rem;color:var(--text-muted);flex-shrink:0">' + escN(new Date(n.created_at).toLocaleDateString()) + '</span>'
          + '</div>';
      }).join('');
    });
  }
})();

// ── AI Intelligence Brief (Gemini-powered) ──────────────────────────────────
function fetchAiBrief(type, id) {
  var card = document.getElementById('ai-brief-card');
  var badge = document.getElementById('ai-brief-badge');
  if (!card) return;

  // Show skeleton loader while fetching
  card.classList.add('ai-brief-loading');
  card.innerHTML = '<div class="ai-brief-skeleton"><div class="ai-skel-row ai-skel-wide"></div><div class="ai-skel-row ai-skel-medium"></div><div class="ai-skel-row ai-skel-wide"></div><div class="ai-skel-row ai-skel-short"></div></div>';

  fetch('/api/ai-context/' + type + '/' + id)
    .then(function(r) {
      if (!r.ok) return r.json().then(function(e) { throw new Error(e.error || 'Error ' + r.status); });
      return r.json();
    })
    .then(function(data) {
      card.classList.remove('ai-brief-loading');
      if (data.cached && badge) badge.style.display = 'inline';

      var s = data.sections;
      var html = '<div class="ai-brief-inner">';

      if (s.attribution_confidence !== undefined) {
        // Threat group
        html += bRow('Attribution Confidence', s.attribution_confidence);
        html += bRow('Sophistication Level', s.sophistication_level);
        html += bList('Primary TTPs', s.primary_ttps);
        html += bPara('Recent Activity', s.recent_activity_assessment);
        html += bList('Targeted Sectors', s.targeted_sectors);
        html += bList('Recommended Defensive Actions', s.recommended_defensive_actions);
        html += bNote(s.analyst_note);
      } else if (s.capability_summary !== undefined) {
        // Malware / software
        html += bPara('Capability Summary', s.capability_summary);
        html += bList('Technical Characteristics', s.technical_characteristics);
        html += bList('Infection Vectors', s.infection_vectors);
        html += bList('Detection Advice', s.detection_advice);
        html += bList('Similar Malware Families', s.similar_malware_families);
        html += bPara('Recent Activity', s.recent_activity_assessment);
        html += bNote(s.analyst_note);
      } else if (s.objectives !== undefined) {
        // Campaign
        html += bPara('Objectives', s.objectives);
        html += bRow('Timeline', s.timeline);
        html += bList('Targeted Sectors', s.targeted_sectors);
        html += bList('Attack Chain', s.attack_chain_summary);
        html += bList('Indicators to Hunt', s.indicators_to_hunt);
        html += bPara('Recent Activity', s.recent_activity_assessment);
        html += bNote(s.analyst_note);
      } else {
        html += '<p class="ai-brief-error">Unexpected response format from AI.</p>';
      }

      html += '<div class="ai-brief-footer">Generated by Gemini AI &middot; '
        + new Date(data.generated_at).toLocaleString() + '</div>';
      html += '</div>';
      card.innerHTML = html;
    })
    .catch(function(err) {
      if (card) {
        card.classList.remove('ai-brief-loading');
        card.innerHTML = '<p class="ai-brief-error">' + escH(err.message || 'AI context unavailable') + '</p>';
      }
    });

  function escH(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function bRow(label, val) {
    if (!val) return '';
    return '<div class="ai-brief-row"><span class="ai-brief-label">' + escH(label) + '</span><span class="ai-brief-value">' + escH(val) + '</span></div>';
  }
  function bPara(label, val) {
    if (!val) return '';
    return '<div class="ai-brief-block"><div class="ai-brief-label">' + escH(label) + '</div><p class="ai-brief-para">' + escH(val) + '</p></div>';
  }
  function bList(label, items) {
    if (!items || !items.length) return '';
    var li = items.map(function(i) { return '<li>' + escH(i) + '</li>'; }).join('');
    return '<div class="ai-brief-block"><div class="ai-brief-label">' + escH(label) + '</div><ul class="ai-brief-list">' + li + '</ul></div>';
  }
  function bNote(val) {
    if (!val) return '';
    return '<div class="ai-brief-highlight">'
      + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;flex-shrink:0;color:#fbbf24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/></svg>'
      + '<span>' + escH(val) + '</span></div>';
  }
}
