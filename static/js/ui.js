/* LockBox shared UI helpers. Loaded on every page via base.html.
   Exposes window.LB. Nothing in here touches passwords or keys. */
(function () {
  'use strict';

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  var LB = (window.LB = {});
  var rootEl = document.documentElement;

  /* ---------- Small utilities ---------- */
  LB.$ = $;
  LB.$$ = $$;

  // Server messages start with emoji (e.g. "⚠️ Please enter..."). The UI has its own icons.
  LB.clean = function (msg) {
    return String(msg == null ? '' : msg).replace(/^[^\p{L}\p{N}]+/u, '').trim();
  };

  LB.icon = function (name, cls) {
    return '<svg class="icon ' + (cls || '') + '" aria-hidden="true"><use href="#i-' + name + '"/></svg>';
  };

  LB.hue = function (str) {
    var h = 0;
    for (var i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) % 360;
    return h;
  };

  LB.timeAgo = function (iso) {
    var d = new Date(iso);
    if (isNaN(d)) return '';
    var s = (Date.now() - d.getTime()) / 1000;
    if (s < 60) return 'Just now';
    var m = Math.floor(s / 60);
    if (m < 60) return m + (m === 1 ? ' minute ago' : ' minutes ago');
    var h = Math.floor(m / 60);
    if (h < 24) return h + (h === 1 ? ' hour ago' : ' hours ago');
    var days = Math.floor(h / 24);
    if (days < 30) return days + (days === 1 ? ' day ago' : ' days ago');
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  };

  /* ---------- Theme ---------- */
  function systemDark() {
    return !!(window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches);
  }
  function applyTheme(pref) {
    var dark = pref === 'dark' || (pref === 'system' && systemDark());
    rootEl.dataset.theme = dark ? 'dark' : 'light';
    rootEl.dataset.themePref = pref;
    document.dispatchEvent(new CustomEvent('lb:theme', { detail: { pref: pref, theme: rootEl.dataset.theme } }));
  }
  LB.getThemePref = function () { return rootEl.dataset.themePref || 'system'; };
  LB.setTheme = function (pref) {
    try { localStorage.setItem('lb-theme', pref); } catch (e) {}
    applyTheme(pref);
  };
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-theme-toggle]');
    if (!btn) return;
    LB.setTheme(rootEl.dataset.theme === 'dark' ? 'light' : 'dark');
  });
  if (window.matchMedia) {
    var mq = matchMedia('(prefers-color-scheme: dark)');
    var onChange = function () { if (LB.getThemePref() === 'system') applyTheme('system'); };
    if (mq.addEventListener) mq.addEventListener('change', onChange);
  }

  /* ---------- Toasts ---------- */
  var ICONS = { success: 'check', error: 'alert', warning: 'alert', info: 'info' };

  function dismissToast(el) {
    if (!el || el.classList.contains('leaving')) return;
    el.classList.add('leaving');
    setTimeout(function () { el.remove(); }, 220);
  }
  function armToast(el, ms) {
    var timer = setTimeout(function () { dismissToast(el); }, ms);
    el.addEventListener('mouseenter', function () { clearTimeout(timer); });
    el.addEventListener('mouseleave', function () { timer = setTimeout(function () { dismissToast(el); }, 2000); });
  }
  LB.toast = function (message, kind, ms) {
    var host = $('#toasts');
    if (!host) return;
    kind = ICONS[kind] ? kind : 'info';
    var el = document.createElement('div');
    el.className = 'toast';
    el.dataset.kind = kind;
    el.innerHTML = LB.icon(ICONS[kind]) +
      '<span class="toast-msg"></span>' +
      '<button type="button" aria-label="Dismiss" data-toast-close>' + LB.icon('x', 'icon-sm') + '</button>';
    el.querySelector('.toast-msg').textContent = LB.clean(message);
    host.appendChild(el);
    // Keep the stack short.
    while (host.children.length > 3) host.firstElementChild.remove();
    armToast(el, ms || (kind === 'error' ? 7000 : 4200));
    return el;
  };
  document.addEventListener('click', function (e) {
    var close = e.target.closest('[data-toast-close]');
    if (close) dismissToast(close.closest('.toast'));
  });

  // A message that should appear on the *next* page (e.g. after being locked out).
  LB.notifyNext = function (message, kind) {
    try { localStorage.setItem('lb-notice', JSON.stringify({ m: message, k: kind || 'info' })); } catch (e) {}
  };

  /* ---------- Dialogs ---------- */
  LB.openDialog = function (dlg) {
    if (!dlg) return;
    dlg.classList.remove('closing');
    if (!dlg.open) dlg.showModal();
  };
  LB.closeDialog = function (dlg, returnValue) {
    if (!dlg || !dlg.open) return;
    dlg.classList.add('closing');
    setTimeout(function () {
      dlg.classList.remove('closing');
      if (dlg.open) dlg.close(returnValue);
    }, 170);
  };
  // Click on the backdrop closes a dialog.
  document.addEventListener('click', function (e) {
    var dlg = e.target;
    if (dlg instanceof HTMLDialogElement && dlg.open) LB.closeDialog(dlg, 'cancel');
  });
  document.addEventListener('click', function (e) {
    var closer = e.target.closest('[data-close-dialog]');
    if (closer) LB.closeDialog(closer.closest('dialog'), 'cancel');
  });

  LB.confirm = function (opts) {
    return new Promise(function (resolve) {
      var dlg = $('#lb-confirm');
      var ok = $('#lb-confirm-ok');
      var cancel = $('#lb-confirm-cancel');
      $('#lb-confirm-title').textContent = opts.title || 'Are you sure?';
      $('#lb-confirm-body').textContent = opts.body || '';
      ok.textContent = opts.confirmText || 'Confirm';
      cancel.textContent = opts.cancelText || 'Cancel';
      ok.className = 'btn ' + (opts.tone === 'danger' ? 'btn-danger' : 'btn-primary');
      dlg.returnValue = '';
      dlg.addEventListener('close', function () { resolve(dlg.returnValue === 'ok'); }, { once: true });
      dlg.showModal();
      (opts.tone === 'danger' ? cancel : ok).focus();
    });
  };

  /* ---------- Busy buttons ---------- */
  // Swaps a button's content for a spinner + label. Returns a function that restores it.
  LB.busy = function (btn, label) {
    if (!btn._lbRestore) {
      var html = btn.innerHTML;
      var wasDisabled = btn.disabled;
      btn._lbRestore = function () {
        btn.innerHTML = html;
        btn.removeAttribute('aria-busy');
        btn.disabled = wasDisabled;
        btn._lbRestore = null;
      };
    }
    btn.setAttribute('aria-busy', 'true');
    btn.textContent = '';
    var spin = document.createElement('span');
    spin.className = 'spinner';
    spin.setAttribute('aria-hidden', 'true');
    var text = document.createElement('span');
    text.textContent = label || '';
    btn.appendChild(spin);
    btn.appendChild(text);
    return btn._lbRestore;
  };

  /* ---------- Clipboard ---------- */
  LB.copy = function (text) {
    var fallback = function () {
      try {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand('copy');
        ta.remove();
        return ok;
      } catch (e) { return false; }
    };
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return fallback(); });
    }
    return Promise.resolve(fallback());
  };

  /* ---------- Fetch helpers ---------- */
  function wentToLogin(res) {
    if (!res.redirected) return false;
    try { return new URL(res.url).pathname.toLowerCase() === '/login'; } catch (e) { return false; }
  }
  // JSON endpoints. `expired` is true when the server bounced us to /login or answered 401.
  LB.api = function (url, opts) {
    opts = opts || {};
    var headers = Object.assign({ 'X-Requested-With': 'XMLHttpRequest' }, opts.headers || {});
    return fetch(url, Object.assign({ credentials: 'same-origin' }, opts, { headers: headers })).then(function (res) {
      // Redirected to /login (idle timeout) or a plain 401 (no session at all): either way the session is over.
      if (wentToLogin(res) || res.status === 401) return { ok: false, expired: true, status: res.status, data: null };
      var ct = res.headers.get('content-type') || '';
      var parse = ct.indexOf('application/json') !== -1 ? res.json().catch(function () { return null; }) : Promise.resolve(null);
      return parse.then(function (data) { return { ok: res.ok, expired: false, status: res.status, data: data }; });
    });
  };
  // Page endpoints: returns a parsed Document so we can swap fragments without a reload.
  LB.page = function (url, opts) {
    return fetch(url, Object.assign({ credentials: 'same-origin' }, opts || {})).then(function (res) {
      if (wentToLogin(res)) return { expired: true, doc: null };
      return res.text().then(function (html) {
        return { expired: false, doc: new DOMParser().parseFromString(html, 'text/html') };
      });
    });
  };

  // Called when the server says the session is over. Wipes the in-browser key.
  LB.sessionOver = function (message) {
    try { sessionStorage.clear(); } catch (e) {}
    LB.notifyNext(message || 'Your session ended. Please log in again.', 'warning');
    window.location.href = '/login';
  };

  /* ---------- Behaviours wired up on load ---------- */
  document.addEventListener('DOMContentLoaded', function () {
    // Year in the footer
    $$('[data-year]').forEach(function (el) { el.textContent = new Date().getFullYear(); });

    // Clean emoji from server-sent messages
    $$('[data-clean]').forEach(function (el) { el.textContent = LB.clean(el.textContent); });
    $$('.toast[data-flash]').forEach(function (el) {
      var msg = el.querySelector('.toast-msg');
      if (msg) msg.textContent = LB.clean(msg.textContent);
      armToast(el, el.dataset.kind === 'error' ? 7000 : 5000);
    });

    // Notice carried over from the previous page
    try {
      var raw = localStorage.getItem('lb-notice');
      if (raw) {
        localStorage.removeItem('lb-notice');
        var n = JSON.parse(raw);
        if (n && n.m) LB.toast(n.m, n.k);
      }
    } catch (e) {}

    // Header gets a hairline once the page scrolls
    var top = $('#site-top');
    if (top) {
      var onScroll = function () { top.classList.toggle('is-scrolled', window.scrollY > 8); };
      window.addEventListener('scroll', onScroll, { passive: true });
      onScroll();
    }

    // Account menu
    $$('[data-menu]').forEach(function (menu) {
      var btn = $('.menu-btn', menu);
      var list = $('.menu-list', menu);
      var close = function () { list.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
      btn.addEventListener('click', function () {
        var open = list.hidden;
        list.hidden = !open;
        btn.setAttribute('aria-expanded', String(open));
      });
      document.addEventListener('click', function (e) { if (!menu.contains(e.target)) close(); });
      menu.addEventListener('keydown', function (e) { if (e.key === 'Escape') { close(); btn.focus(); } });
    });

    // Show / hide for password inputs: <button data-toggle-visibility="inputId">
    document.addEventListener('click', function (e) {
      var btn = e.target.closest('[data-toggle-visibility]');
      if (!btn) return;
      var input = document.getElementById(btn.dataset.toggleVisibility);
      if (!input) return;
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.setAttribute('aria-pressed', String(show));
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      var use = btn.querySelector('use');
      if (use) use.setAttribute('href', show ? '#i-eye-off' : '#i-eye');
    });

    // Logging out also clears the in-browser key.
    document.addEventListener('click', function (e) {
      if (e.target.closest('[data-logout]')) { try { sessionStorage.clear(); } catch (err) {} }
    });
  });
})();
