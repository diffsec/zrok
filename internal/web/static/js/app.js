// app.js — minimal bootstrap. Reads the CSRF token from the page <meta> tag and
// configures htmx (if loaded) to attach it as a request header. PR-5 wires
// alpine.js and the live SSE listeners for the run view + transcript drawer.
(function () {
  var meta = document.querySelector('meta[name="csrf-token"]');
  var token = meta ? meta.getAttribute('content') : '';
  if (!token) return;
  document.addEventListener('htmx:configRequest', function (e) {
    e.detail.headers['X-CSRF-Token'] = token;
  });
})();
