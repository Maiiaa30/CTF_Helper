/* ============================================================
   CTF Helper — application bootstrap
   ============================================================ */
(function () {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  /* ---------- toast ---------- */
  let toastTimer;
  function toast(msg, accent = true) {
    const el = $("#toast");
    el.innerHTML = accent ? `<span class="toast-accent">✓</span>${msg}` : msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 1600);
  }

  /* ---------- target panel (visibility only; persistence added later) ---------- */
  function initTargetPanel() {
    const toggle = $("#targetToggle");
    const panel = $("#targetPanel");
    toggle.addEventListener("click", () => {
      panel.hidden = !panel.hidden;
    });
  }

  /* ---------- expose a tiny shared namespace ---------- */
  window.CTF = { $, $$, toast };

  document.addEventListener("DOMContentLoaded", () => {
    initTargetPanel();
  });
})();
