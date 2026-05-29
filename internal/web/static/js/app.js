// app.js — wires CSRF on every htmx request, exposes a tiny modal helper,
// and initializes Sortable.js on any element flagged with data-sortable.
// Alpine.js, HTMX, the HTMX SSE extension, and Sortable.js are loaded as
// separate <script> tags from layout.templ (all vendored under /static/js/vendor/).
(function () {
  var meta = document.querySelector('meta[name="csrf-token"]');
  var token = meta ? meta.getAttribute('content') : '';

  // Stamp the CSRF token onto every htmx request (header) and into any
  // hx-vals form-encoded request bodies (htmx already includes form fields).
  document.addEventListener('htmx:configRequest', function (e) {
    if (token) {
      e.detail.headers['X-CSRF-Token'] = token;
    }
  });

  // Open htmx-driven modals. Server returns a <dialog> partial which we
  // inject into #modal-slot and immediately showModal().
  document.body.addEventListener('htmx:afterSwap', function (e) {
    var slot = document.getElementById('modal-slot');
    if (!slot) return;
    if (e.detail.target !== slot) return;
    var dlg = slot.querySelector('dialog');
    if (dlg && typeof dlg.showModal === 'function' && !dlg.open) {
      dlg.showModal();
    }
  });

  // Close button inside modals.
  document.body.addEventListener('click', function (e) {
    var btn = e.target;
    if (!(btn instanceof HTMLElement)) return;
    if (btn.matches('[data-close-modal]') || btn.closest('[data-close-modal]')) {
      var dlg = btn.closest('dialog');
      if (dlg) dlg.close();
    }
  });

  // Wire Sortable on elements with data-sortable. Wraps the input array of
  // <li data-id="X"> with a hidden field tracking the new order.
  function wireSortables() {
    if (typeof Sortable === 'undefined') return;
    document.querySelectorAll('[data-sortable]').forEach(function (el) {
      if (el._sortableWired) return;
      el._sortableWired = true;
      Sortable.create(el, {
        animation: 150,
        handle: '[data-sortable-handle]',
        onEnd: function () {
          var order = Array.from(el.querySelectorAll('[data-id]')).map(function (n) {
            return n.getAttribute('data-id');
          });
          var hidden = document.querySelector(el.getAttribute('data-order-target'));
          if (hidden) hidden.value = order.join(',');
        }
      });
    });
  }

  document.addEventListener('DOMContentLoaded', wireSortables);
  document.body.addEventListener('htmx:afterSwap', wireSortables);
})();

// Alpine helpers: bulk-select state. Each findings list mounts
// x-data="bulkSelect()".
window.bulkSelect = function () {
  return {
    selected: new Set(),
    toggle: function (id) {
      if (this.selected.has(id)) this.selected.delete(id);
      else this.selected.add(id);
    },
    isSelected: function (id) { return this.selected.has(id); },
    clear: function () { this.selected.clear(); },
    ids: function () { return Array.from(this.selected); },
    count: function () { return this.selected.size; }
  };
};
