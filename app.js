/* ============================================================
   CTF Helper — application
   ============================================================ */
(function () {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const ICONS = {
    copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>'
  };

  /* ---------- toast ---------- */
  let toastTimer;
  function toast(msg, accent = true) {
    const el = $("#toast");
    el.innerHTML = accent ? `<span class="toast-accent">✓</span>${msg}` : msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 1600);
  }

  /* ---------- storage ---------- */
  const STORE = {
    get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
    del(k) { try { localStorage.removeItem(k); } catch (e) {} }
  };

  /* ---------- helpers ---------- */
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      // fallback for non-secure contexts
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch (_) {}
      document.body.removeChild(ta);
      return ok;
    }
  }

  /* ---------- copy button wiring (text can be static or a getter) ---------- */
  function attachCopy(btn, getText) {
    btn.addEventListener("click", async () => {
      const text = typeof getText === "function" ? getText() : getText;
      const ok = await copyText(text);
      if (!ok) { toast("Copy failed", false); return; }
      btn.classList.add("copied");
      const prev = btn.innerHTML;
      btn.innerHTML = ICONS.check;
      toast("Copied to clipboard");
      setTimeout(() => { btn.classList.remove("copied"); btn.innerHTML = prev; }, 1100);
    });
  }

  /* ---------- command block ---------- */
  function cmdBlock(item) {
    const el = document.createElement("div");
    el.className = "cmd";
    el.dataset.search = (item.cmd + " " + item.desc + " " + (item.tags || []).join(" ")).toLowerCase();

    const tags = (item.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join("");

    el.innerHTML = `
      ${item.desc ? `<div class="cmd-desc">${esc(item.desc)}</div>` : ""}
      <div class="cmd-body">
        <pre class="cmd-code">${esc(item.cmd)}</pre>
        <div class="cmd-actions">
          <button class="icon-btn copy-btn" title="Copy">${ICONS.copy}</button>
        </div>
      </div>
      ${tags ? `<div class="cmd-tags">${tags}</div>` : ""}
    `;

    attachCopy($(".copy-btn", el), item.cmd);
    return el;
  }

  /* ---------- reverse shell generator ---------- */
  function substitute(tpl, lhost, lport) {
    return tpl.replace(/\{\{LHOST\}\}/g, lhost || "LHOST").replace(/\{\{LPORT\}\}/g, lport || "LPORT");
  }

  function revBlock(name, cmd) {
    const el = document.createElement("div");
    el.className = "cmd";
    el.dataset.search = (name + " " + cmd).toLowerCase();
    el.innerHTML = `
      <span class="shell-name">${esc(name)}</span>
      <div class="cmd-body">
        <pre class="cmd-code">${esc(cmd)}</pre>
        <div class="cmd-actions"><button class="icon-btn copy-btn" title="Copy">${ICONS.copy}</button></div>
      </div>`;
    attachCopy($(".copy-btn", el), cmd);
    return el;
  }

  function renderRevshell(group) {
    const wrap = document.createElement("div");
    wrap.className = "group";
    wrap.dataset.group = group.id;

    const head = document.createElement("button");
    head.className = "group-head";
    head.innerHTML = `<span class="group-caret">▾</span><span>${esc(group.title)}</span><span class="group-count">${REVSHELLS.length}</span>`;
    head.addEventListener("click", () => wrap.classList.toggle("collapsed"));
    wrap.appendChild(head);

    if (group.note) {
      const note = document.createElement("div");
      note.className = "group-note";
      note.textContent = group.note;
      wrap.appendChild(note);
    }

    const saved = STORE.get("ctf.rev", { lhost: "", lport: "" });
    const controls = document.createElement("div");
    controls.className = "rev-controls";
    controls.innerHTML = `
      <label class="field">
        <span class="field-label">LHOST</span>
        <input id="revLhost" class="field-input mono" placeholder="10.10.14.1" autocomplete="off" value="${esc(saved.lhost || "")}">
      </label>
      <label class="field">
        <span class="field-label">LPORT</span>
        <input id="revLport" class="field-input mono" placeholder="4444" autocomplete="off" value="${esc(saved.lport || "")}">
      </label>`;
    wrap.appendChild(controls);

    const listenHead = document.createElement("div");
    listenHead.className = "rev-subhead";
    listenHead.textContent = "Listener";
    wrap.appendChild(listenHead);
    const listenList = document.createElement("div");
    listenList.className = "block-list";
    wrap.appendChild(listenList);

    const shellHead = document.createElement("div");
    shellHead.className = "rev-subhead";
    shellHead.textContent = "Payloads";
    wrap.appendChild(shellHead);
    const shellList = document.createElement("div");
    shellList.className = "block-list";
    wrap.appendChild(shellList);

    const lhostIn = $("#revLhost", controls);
    const lportIn = $("#revLport", controls);

    function build() {
      const lhost = lhostIn.value.trim();
      const lport = lportIn.value.trim();
      listenList.innerHTML = "";
      LISTENERS.forEach((l) => listenList.appendChild(revBlock(l.name, substitute(l.cmd, lhost, lport))));
      shellList.innerHTML = "";
      REVSHELLS.forEach((s) => shellList.appendChild(revBlock(s.name, substitute(s.cmd, lhost, lport))));
    }

    let t;
    function onInput() {
      STORE.set("ctf.rev", { lhost: lhostIn.value.trim(), lport: lportIn.value.trim() });
      clearTimeout(t);
      t = setTimeout(build, 60);
    }
    lhostIn.addEventListener("input", onInput);
    lportIn.addEventListener("input", onInput);
    build();

    return wrap;
  }

  /* ---------- render one group ---------- */
  /* shared group shell: wrap + collapsible head + optional note */
  function groupShell(group, count) {
    const wrap = document.createElement("div");
    wrap.className = "group";
    wrap.dataset.group = group.id;

    const head = document.createElement("button");
    head.className = "group-head";
    head.innerHTML = `<span class="group-caret">▾</span><span>${esc(group.title)}</span><span class="group-count">${count}</span>`;
    head.addEventListener("click", () => wrap.classList.toggle("collapsed"));
    wrap.appendChild(head);

    if (group.note) {
      const note = document.createElement("div");
      note.className = "group-note";
      note.textContent = group.note;
      wrap.appendChild(note);
    }
    return wrap;
  }

  function refList(items) {
    const list = document.createElement("div");
    list.className = "ref-list";
    items.forEach((it) => {
      const row = document.createElement("div");
      row.className = "ref-row";
      row.dataset.search = (it.term + " " + it.desc).toLowerCase();
      row.innerHTML = `<span class="ref-term mono">${esc(it.term)}</span><span class="ref-desc">${esc(it.desc)}</span>`;
      list.appendChild(row);
    });
    return list;
  }

  function checklist(items) {
    const list = document.createElement("div");
    list.className = "check-list";
    items.forEach((text) => {
      const row = document.createElement("button");
      row.className = "check-row";
      row.type = "button";
      row.dataset.search = String(text).toLowerCase();
      row.innerHTML = `<span class="check-box"></span><span class="check-text">${esc(text)}</span>`;
      row.addEventListener("click", () => row.classList.toggle("done"));
      list.appendChild(row);
    });
    return list;
  }

  function dataTable(group) {
    const wrap = document.createElement("div");
    wrap.className = "table-wrap";
    const cols = group.columns || [];
    const head = cols.map((c) => `<th>${esc(c)}</th>`).join("");
    const body = (group.rows || [])
      .map((r) => `<tr data-search="${esc(r.join(" ").toLowerCase())}">` + r.map((c) => `<td>${esc(c)}</td>`).join("") + "</tr>")
      .join("");
    wrap.innerHTML = `<table class="ref-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
    return wrap;
  }

  function linkList(items) {
    const list = document.createElement("div");
    list.className = "link-list";
    items.forEach((it) => {
      const a = document.createElement("a");
      a.className = "link-card";
      a.href = it.url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.dataset.search = (it.label + " " + (it.note || "") + " " + it.url).toLowerCase();
      a.innerHTML = `
        <span class="link-label">${esc(it.label)} <span class="link-ext">↗</span></span>
        ${it.note ? `<span class="link-note">${esc(it.note)}</span>` : ""}`;
      list.appendChild(a);
    });
    return list;
  }

  function renderGroup(cat, group) {
    if (group.type === "revshell") return renderRevshell(group);

    const n = group.type === "table" ? (group.rows || []).length : (group.items || []).length;
    const wrap = groupShell(group, n);

    if (group.type === "ref") {
      wrap.appendChild(refList(group.items || []));
    } else if (group.type === "checklist") {
      wrap.appendChild(checklist(group.items || []));
    } else if (group.type === "table") {
      wrap.appendChild(dataTable(group));
    } else if (group.type === "links") {
      wrap.appendChild(linkList(group.items || []));
    } else {
      const list = document.createElement("div");
      list.className = "block-list";
      (group.items || []).forEach((item) => list.appendChild(cmdBlock(item)));
      wrap.appendChild(list);
    }
    return wrap;
  }

  /* ---------- render all sections ---------- */
  function renderSections() {
    const root = $("#sections");
    root.innerHTML = "";

    CTF_DATA.forEach((cat) => {
      const sec = document.createElement("section");
      sec.className = "cat-section";
      sec.id = "cat-" + cat.id;
      sec.dataset.cat = cat.id;

      sec.innerHTML = `
        <h2 class="cat-title"><span class="cat-emoji">${cat.emoji || ""}</span>${esc(cat.title)}</h2>
        ${cat.desc ? `<p class="cat-desc">${esc(cat.desc)}</p>` : ""}
      `;

      (cat.groups || []).forEach((group) => sec.appendChild(renderGroup(cat, group)));
      root.appendChild(sec);
    });
  }

  /* ---------- sidebar ---------- */
  function renderSidebar() {
    const nav = $("#sidebar");
    nav.innerHTML = "";

    CTF_DATA.forEach((cat) => {
      const catEl = document.createElement("div");
      catEl.className = "nav-cat";

      const head = document.createElement("button");
      head.className = "nav-cat-head";
      head.innerHTML = `
        <span class="nav-cat-icon">${cat.emoji || "•"}</span>
        <span>${esc(cat.title)}</span>
        <span class="nav-cat-caret">▾</span>
      `;
      catEl.appendChild(head);

      const links = document.createElement("div");
      links.className = "nav-links";
      (cat.groups || []).forEach((group) => {
        const link = document.createElement("button");
        link.className = "nav-link";
        link.textContent = group.title;
        link.dataset.target = "cat-" + cat.id;
        link.dataset.group = group.id;
        link.addEventListener("click", () => {
          const sec = document.getElementById("cat-" + cat.id);
          if (sec) sec.scrollIntoView({ behavior: "smooth", block: "start" });
          $("#sidebar").classList.remove("open");
        });
        links.appendChild(link);
      });
      catEl.appendChild(links);

      head.addEventListener("click", () => catEl.classList.toggle("collapsed"));
      nav.appendChild(catEl);
    });
  }

  /* ---------- scroll spy ---------- */
  function initScrollSpy() {
    const sections = $$(".cat-section");
    if (!("IntersectionObserver" in window) || !sections.length) return;
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          const id = entry.target.id;
          $$(".nav-link").forEach((l) => l.classList.toggle("active", l.dataset.target === id));
        });
      },
      { rootMargin: "-20% 0px -70% 0px" }
    );
    sections.forEach((s) => obs.observe(s));
  }

  /* ---------- target panel (persisted) ---------- */
  function initTargetPanel() {
    const panel = $("#targetPanel");
    const dot = $("#targetDot");
    const savedMsg = $("#targetSaved");
    const fields = { host: $("#tgtHost"), ports: $("#tgtPorts"), phase: $("#tgtPhase"), notes: $("#tgtNotes") };

    const data = STORE.get("ctf.target", {});
    Object.keys(fields).forEach((k) => { if (data[k] != null) fields[k].value = data[k]; });

    function refreshDot() { dot.classList.toggle("active", !!fields.host.value.trim()); }
    refreshDot();

    // remember panel open state
    if (STORE.get("ctf.targetOpen", false)) panel.hidden = false;

    let savedTimer;
    function save() {
      const out = {};
      Object.keys(fields).forEach((k) => { out[k] = fields[k].value; });
      STORE.set("ctf.target", out);
      refreshDot();
      savedMsg.classList.add("show");
      clearTimeout(savedTimer);
      savedTimer = setTimeout(() => savedMsg.classList.remove("show"), 1200);
    }
    Object.values(fields).forEach((el) => el.addEventListener("input", save));

    $("#targetToggle").addEventListener("click", () => {
      panel.hidden = !panel.hidden;
      STORE.set("ctf.targetOpen", !panel.hidden);
    });

    $("#targetClear").addEventListener("click", () => {
      Object.values(fields).forEach((el) => { el.value = el.tagName === "SELECT" ? el.options[0].value : ""; });
      STORE.del("ctf.target");
      refreshDot();
      toast("Target cleared");
    });
  }

  /* ---------- shared namespace ---------- */
  window.CTF = { $, $$, toast, esc, copyText, ICONS };

  document.addEventListener("DOMContentLoaded", () => {
    renderSidebar();
    renderSections();
    initScrollSpy();
    initTargetPanel();
  });
})();
