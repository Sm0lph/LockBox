/* LockBox password generator + strength estimate.
   Uses crypto.getRandomValues (not Math.random) with rejection sampling so
   every character is chosen uniformly. Exposes window.LBGen. */
(function () {
  'use strict';

  var SETS = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{};:,.?'
  };
  var LOOKALIKES = /[Il1O0o|]/g;
  var COMMON = ['password', 'passw0rd', 'qwerty', 'letmein', 'welcome', 'admin', 'iloveyou', 'monkey', 'dragon', 'football', 'abc123', '123456', '111111', 'login'];

  // Uniform random integer in [0, max)
  function randInt(max) {
    var limit = Math.floor(0x100000000 / max) * max;
    var buf = new Uint32Array(1);
    do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % max;
  }

  function activeSets(opts) {
    var out = [];
    ['lower', 'upper', 'digits', 'symbols'].forEach(function (name) {
      if (!opts[name]) return;
      var chars = SETS[name];
      if (opts.avoidLookalikes) chars = chars.replace(LOOKALIKES, '');
      if (chars.length) out.push(chars);
    });
    return out;
  }

  // opts: { length, lower, upper, digits, symbols, avoidLookalikes }
  function generate(opts) {
    var sets = activeSets(opts);
    var length = Math.max(sets.length, Math.min(opts.length || 16, 128));
    if (!sets.length) return '';
    var pool = sets.join('');
    var out = [];
    // One guaranteed character from each chosen set...
    sets.forEach(function (s) { out.push(s[randInt(s.length)]); });
    // ...then fill the rest from the whole pool.
    while (out.length < length) out.push(pool[randInt(pool.length)]);
    // Fisher-Yates shuffle so the guaranteed ones are not always first.
    for (var i = out.length - 1; i > 0; i--) {
      var j = randInt(i + 1);
      var t = out[i]; out[i] = out[j]; out[j] = t;
    }
    return out.join('');
  }

  function poolSize(opts) {
    return activeSets(opts).join('').length;
  }

  // Entropy of a password produced by generate(): length * log2(pool)
  function generatedBits(opts, length) {
    var p = poolSize(opts);
    return p > 1 ? Math.round((length || opts.length) * Math.log2(p)) : 0;
  }

  // Rough, deliberately cautious estimate for a password a person typed. Heuristic, not a guarantee.
  function estimateBits(pw) {
    if (!pw) return 0;
    var pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/\d/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 28;
    // Word-like runs (4+ letters in a row) are far easier to guess than random letters,
    // so they are charged ~2.6 bits per character instead of the full alphabet.
    var wordChars = 0;
    (pw.match(/[A-Za-z]{4,}/g) || []).forEach(function (w) { wordChars += w.length; });
    var bits = (pw.length - wordChars) * Math.log2(Math.max(pool, 2)) + wordChars * 2.6;

    var lower = pw.toLowerCase();
    if (COMMON.some(function (w) { return lower.indexOf(w) !== -1; })) bits = Math.min(bits, 28) * 0.6;
    if (/(.)\1{2,}/.test(pw)) bits -= 8;
    if (/(abc|bcd|cde|def|efg|qwe|wer|ert|asd|sdf|012|123|234|345|456|567|678|789)/i.test(pw)) bits -= 8;
    // Few distinct characters means a small effective alphabet.
    var distinct = new Set(pw.split('')).size;
    if (distinct < pw.length / 2) bits -= 10;
    return Math.max(0, Math.round(bits));
  }

  // 0 = empty, 1..4 = weak..excellent
  function level(bits) {
    if (!bits) return 0;
    if (bits < 40) return 1;
    if (bits < 60) return 2;
    if (bits < 80) return 3;
    return 4;
  }
  var NAMES = ['', 'Weak', 'Fair', 'Strong', 'Excellent'];

  // Paint a .meter element + optional label element.
  function paint(meterEl, labelEl, bits) {
    var lv = level(bits);
    if (meterEl) meterEl.dataset.level = String(lv);
    if (labelEl) {
      labelEl.innerHTML = lv
        ? '<strong>' + NAMES[lv] + '</strong><span>about ' + bits + ' bits</span>'
        : '<span>Enter a password to see its strength</span><span></span>';
    }
    return lv;
  }

  window.LBGen = {
    SETS: SETS,
    generate: generate,
    generatedBits: generatedBits,
    estimateBits: estimateBits,
    level: level,
    levelName: function (bits) { return NAMES[level(bits)]; },
    paint: paint
  };
})();
