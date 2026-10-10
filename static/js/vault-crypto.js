/* LockBox vault crypto (client-side).

   This keeps the SAME scheme as the original Login.html / Dashboard.html so
   every password already saved in your database still decrypts:

     key   = PBKDF2(masterPassword, base64-decoded master_salt,
                    256-bit, 100,000 iterations, HMAC-SHA1)
     cipher= AES-256-CBC, PKCS7 padding, random 128-bit IV per entry
     store = ciphertext (Base64) + IV (Base64)

   HMAC-SHA1 is written out explicitly on purpose. CryptoJS < 4.2.0 used SHA-1
   as the PBKDF2 default and 4.2.0+ silently switched to SHA-256, which would
   derive a different key and make existing entries undecryptable.

   Requires CryptoJS to be loaded first. Exposes window.LBCrypto. */
(function () {
  'use strict';

  var ITERATIONS = 100000;

  function lib() {
    if (!window.CryptoJS) throw new Error('The encryption library did not load. Check your connection and reload.');
    return window.CryptoJS;
  }

  function deriveKeyHex(masterPassword, masterSaltB64) {
    var C = lib();
    var salt = C.enc.Base64.parse(masterSaltB64);
    var key = C.PBKDF2(masterPassword, salt, {
      keySize: 256 / 32,
      iterations: ITERATIONS,
      hasher: C.algo.SHA1
    });
    return key.toString(C.enc.Hex);
  }

  function encrypt(plainText, keyHex) {
    var C = lib();
    var key = C.enc.Hex.parse(keyHex);
    var iv = C.lib.WordArray.random(128 / 8);
    var encrypted = C.AES.encrypt(plainText, key, {
      iv: iv,
      mode: C.mode.CBC,
      padding: C.pad.Pkcs7
    });
    return { ciphertext: encrypted.toString(), iv: iv.toString(C.enc.Base64) };
  }

  // Returns the plaintext, or null if it cannot be decrypted with this key.
  function decrypt(cipherB64, ivB64, keyHex) {
    try {
      var C = lib();
      var key = C.enc.Hex.parse(keyHex);
      var iv = C.enc.Base64.parse(ivB64);
      var decrypted = C.AES.decrypt(cipherB64, key, {
        iv: iv,
        mode: C.mode.CBC,
        padding: C.pad.Pkcs7
      });
      return decrypted.toString(C.enc.Utf8) || null;
    } catch (e) {
      return null;
    }
  }

  // sessionStorage keys written at login and read by the vault
  var KEYS = { key: 'aesKey', salt: 'masterSalt', user: 'userId' };

  window.LBCrypto = {
    deriveKeyHex: deriveKeyHex,
    encrypt: encrypt,
    decrypt: decrypt,
    getKey: function () { return sessionStorage.getItem(KEYS.key); },
    hasSession: function () {
      return !!(sessionStorage.getItem(KEYS.key) && sessionStorage.getItem(KEYS.salt) && sessionStorage.getItem(KEYS.user));
    },
    saveSession: function (keyHex, masterSalt, userId) {
      sessionStorage.setItem(KEYS.key, keyHex);
      sessionStorage.setItem(KEYS.salt, masterSalt);
      sessionStorage.setItem(KEYS.user, String(userId));
    },
    clear: function () { sessionStorage.clear(); }
  };
})();
