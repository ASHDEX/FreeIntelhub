// Theme toggle — supports both sidebar and mobile toggle buttons
(function() {
  var saved = localStorage.getItem('theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);

  function toggleTheme() {
    var current = document.documentElement.getAttribute('data-theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
  }

  var btn = document.getElementById('theme-toggle');
  if (btn) btn.addEventListener('click', toggleTheme);

  var btnMobile = document.getElementById('theme-toggle-mobile');
  if (btnMobile) btnMobile.addEventListener('click', toggleTheme);
})();

// Sidebar: collapse, mobile open/close
(function() {
  var sidebar = document.getElementById('sidebar');
  var mainWrapper = document.getElementById('main-wrapper');
  var collapseBtn = document.getElementById('sidebar-collapse');
  var mobileMenuBtn = document.getElementById('mobile-menu-btn');
  var overlay = document.getElementById('sidebar-overlay');

  if (!sidebar) return;

  // Restore collapsed state from localStorage
  var isCollapsed = localStorage.getItem('sidebar-collapsed') === '1';
  if (isCollapsed) {
    sidebar.classList.add('collapsed');
    if (mainWrapper) mainWrapper.classList.add('with-sidebar-collapsed');
  }

  // Collapse / expand on desktop
  if (collapseBtn) {
    collapseBtn.addEventListener('click', function() {
      sidebar.classList.toggle('collapsed');
      if (mainWrapper) mainWrapper.classList.toggle('with-sidebar-collapsed');
      var nowCollapsed = sidebar.classList.contains('collapsed');
      localStorage.setItem('sidebar-collapsed', nowCollapsed ? '1' : '0');
      // Flip the collapse icon direction
      var svg = collapseBtn.querySelector('svg');
      if (svg) svg.style.transform = nowCollapsed ? 'rotate(180deg)' : '';
    });
    // Set initial icon direction
    if (isCollapsed) {
      var svg = collapseBtn.querySelector('svg');
      if (svg) svg.style.transform = 'rotate(180deg)';
    }
  }

  // Mobile menu open/close
  function openMobile() {
    sidebar.classList.add('mobile-open');
    if (overlay) overlay.classList.add('visible');
    document.body.style.overflow = 'hidden';
  }
  function closeMobile() {
    sidebar.classList.remove('mobile-open');
    if (overlay) overlay.classList.remove('visible');
    document.body.style.overflow = '';
  }

  if (mobileMenuBtn) mobileMenuBtn.addEventListener('click', openMobile);
  if (overlay) overlay.addEventListener('click', closeMobile);

  // Close sidebar on Escape
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && sidebar.classList.contains('mobile-open')) closeMobile();
  });
})();

// Sidebar dropdown toggles
function toggleDropdown(id, btn) {
  var dd = document.getElementById(id);
  if (!dd) return;
  var isOpen = dd.classList.contains('open');
  dd.classList.toggle('open');

  // Rotate chevron
  var chevron = btn.querySelector('.sidebar-chevron');
  if (chevron) chevron.classList.toggle('rotated', !isOpen);
}

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
