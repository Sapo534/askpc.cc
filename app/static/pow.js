(function () {
  var form = document.getElementById('register-form');
  if (!form) return;
  var salt = form.dataset.salt;
  var bits = parseInt(form.dataset.bits, 10);
  var nonceInput = form.querySelector('input[name="pow_nonce"]');
  var btn = document.getElementById('register-submit');
  var label = btn.textContent;
  var enc = new TextEncoder();

  function leadingZeroBits(buf) {
    var a = new Uint8Array(buf), n = 0;
    for (var i = 0; i < a.length; i++) {
      if (a[i] === 0) { n += 8; continue; }
      n += Math.clz32(a[i]) - 24;
      break;
    }
    return n;
  }

  btn.textContent = 'Checking…';
  (async function () {
    for (var nonce = 0; ; nonce++) {
      var h = await crypto.subtle.digest('SHA-256', enc.encode(salt + ':' + nonce));
      if (leadingZeroBits(h) >= bits) break;
    }
    nonceInput.value = nonce;
    btn.disabled = false;
    btn.textContent = label;
  })();
})();
