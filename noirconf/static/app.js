// Page helpers. No inline script is allowed by the CSP.
(function () {
  "use strict";

  // Fill a textarea from a chosen file (no upload to the server).
  document.addEventListener("change", function (ev) {
    var input = ev.target;
    if (!input || input.type !== "file" || !input.dataset.fill) return;
    var file = input.files && input.files[0];
    if (!file || file.size > 100000) return;
    var area = input.form.querySelector('[name="' + input.dataset.fill + '"]');
    if (!area) return;
    var reader = new FileReader();
    reader.onload = function () { area.value = String(reader.result); };
    reader.readAsText(file);
  });

  // Run as TLS server: the protocol list does not apply, so it is disabled. A disabled
  // control is not posted, and the server writes proto tls-server.
  function syncTls() {
    var box = document.getElementById("v-tls");
    var sel = document.querySelector('select[name="o.proto"]');
    if (box && sel) sel.disabled = box.checked;
  }
  document.addEventListener("change", function (ev) {
    if (ev.target && ev.target.id === "v-tls") syncTls();
  });
  document.addEventListener("htmx:afterSettle", syncTls);
  document.addEventListener("DOMContentLoaded", syncTls);

  // Create with Essentials: the WebSocket path follows the server name until the user edits it.
  document.addEventListener("input", function (ev) {
    var t = ev.target;
    if (!t) return;
    if (t.id === "f-ws") {
      t.dataset.auto = "0";
    } else if (t.id === "f-name") {
      var ws = document.getElementById("f-ws");
      if (ws && ws.dataset.auto !== "0") ws.value = "/noir-" + (t.value || "server");
    }
  });

  // The pages answer a rejected form with status 400 and the form again: show it.
  document.addEventListener("htmx:beforeSwap", function (ev) {
    var d = ev.detail;
    if (d && d.xhr && d.xhr.status === 400) {
      d.shouldSwap = true;
      d.isError = false;
    }
  });

  // A click on a menu item closes the menu on a narrow screen.
  document.addEventListener("click", function (ev) {
    var t = ev.target;
    if (t && t.closest && t.closest("#main-nav a")) {
      var box = document.getElementById("nav-toggle");
      if (box) box.checked = false;
    }
  });

  // An expired session returns 401: go to the login page.
  document.addEventListener("htmx:responseError", function (ev) {
    if (ev.detail && ev.detail.xhr && ev.detail.xhr.status === 401) {
      window.location.href = "/login";
    }
  });
})();
