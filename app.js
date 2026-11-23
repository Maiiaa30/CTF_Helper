/* ============================================================
   CTF Helper — application
   ============================================================ */
(function () {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const ICONS = {
    copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    pin: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>',
    pinFilled: '<svg viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>'
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

  /* ---------- pins ---------- */
  let pins = STORE.get("ctf.pins", []);
  const itemIndex = new Map(); // cmd -> item

  function isPinned(cmd) { return pins.indexOf(cmd) !== -1; }
  function togglePin(cmd) {
    const i = pins.indexOf(cmd);
    if (i === -1) { pins.push(cmd); toast("Pinned to Quick Access"); }
    else { pins.splice(i, 1); toast("Unpinned"); }
    STORE.set("ctf.pins", pins);
    refreshPins();
  }

  /* ---------- collapse persistence ---------- */
  function saveCollapsed() {
    const ids = $$(".group.collapsed").map((g) => g.dataset.group);
    STORE.set("ctf.collapsed", ids);
  }
  function applyCollapsed() {
    const ids = STORE.get("ctf.collapsed", []);
    $$(".group").forEach((g) => g.classList.toggle("collapsed", ids.indexOf(g.dataset.group) !== -1));
  }

  /* ---------- category tabs ---------- */
  let activeCat = null;

  function applyAccordion() {
    $$(".nav-cat").forEach((c) => c.classList.toggle("collapsed", c.dataset.cat !== activeCat));
  }

  function setActive(catId, scrollTop = true) {
    if (!CTF_DATA.some((c) => c.id === catId)) catId = CTF_DATA[0].id;
    activeCat = catId;
    STORE.set("ctf.activeCat", catId);
    $$(".cat-section").forEach((s) => s.classList.toggle("inactive", s.dataset.cat !== catId));
    $$(".nav-cat").forEach((c) => c.classList.toggle("active-cat", c.dataset.cat === catId));
    if (!document.body.classList.contains("searching")) applyAccordion();
    if (scrollTop) window.scrollTo({ top: 0, behavior: "smooth" });
  }

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
    itemIndex.set(item.cmd, item);

    const el = document.createElement("div");
    el.className = "cmd";
    el.dataset.cmd = item.cmd;
    el.dataset.search = (item.cmd + " " + item.desc + " " + (item.tags || []).join(" ")).toLowerCase();

    const tags = (item.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join("");
    const pinned = isPinned(item.cmd);

    el.innerHTML = `
      ${item.desc ? `<div class="cmd-desc">${esc(item.desc)}</div>` : ""}
      <div class="cmd-body">
        <pre class="cmd-code">${esc(item.cmd)}</pre>
        <div class="cmd-actions">
          <button class="icon-btn pin-btn ${pinned ? "pinned" : ""}" title="Pin to Quick Access">${pinned ? ICONS.pinFilled : ICONS.pin}</button>
          <button class="icon-btn copy-btn" title="Copy">${ICONS.copy}</button>
        </div>
      </div>
      ${tags ? `<div class="cmd-tags">${tags}</div>` : ""}
    `;

    attachCopy($(".copy-btn", el), item.cmd);
    $(".pin-btn", el).addEventListener("click", () => togglePin(item.cmd));
    return el;
  }

  /* ---------- quick access (pinned) ---------- */
  function renderQuickAccess() {
    const section = $("#quickAccess");
    const list = $("#pinnedList");
    list.innerHTML = "";
    const valid = pins.filter((c) => itemIndex.has(c));
    if (!valid.length) { section.hidden = true; return; }
    section.hidden = false;
    valid.forEach((c) => list.appendChild(cmdBlock(itemIndex.get(c))));
  }

  function refreshPins() {
    $$(".pin-btn").forEach((btn) => {
      const cmd = btn.closest(".cmd").dataset.cmd;
      const on = isPinned(cmd);
      btn.classList.toggle("pinned", on);
      btn.innerHTML = on ? ICONS.pinFilled : ICONS.pin;
    });
    renderQuickAccess();
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
    head.addEventListener("click", () => { wrap.classList.toggle("collapsed"); saveCollapsed(); });
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
    listenList.className = "block-list no-grid";
    wrap.appendChild(listenList);

    const shellHead = document.createElement("div");
    shellHead.className = "rev-subhead";
    shellHead.textContent = "Payloads";
    wrap.appendChild(shellHead);
    const shellList = document.createElement("div");
    shellList.className = "block-list no-grid";
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
    head.addEventListener("click", () => { wrap.classList.toggle("collapsed"); saveCollapsed(); });
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
      catEl.dataset.cat = cat.id;

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
          if (activeCat !== cat.id) setActive(cat.id, false);
          const grp = document.querySelector('#cat-' + cat.id + ' .group[data-group="' + group.id + '"]');
          if (grp) grp.scrollIntoView({ behavior: "smooth", block: "start" });
          $("#sidebar").classList.remove("open");
        });
        links.appendChild(link);
      });
      catEl.appendChild(links);

      head.addEventListener("click", () => {
        setActive(cat.id);
        $("#sidebar").classList.remove("open");
      });
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

  /* ---------- search / filter ---------- */
  function runSearch(q) {
    const tokens = q.toLowerCase().split(/\s+/).filter(Boolean);
    const searching = tokens.length > 0;
    document.body.classList.toggle("searching", searching);

    // expand all groups + nav while searching so matches are visible across tabs
    if (searching) {
      $$("#sections .group").forEach((g) => g.classList.remove("collapsed"));
      $$(".nav-cat").forEach((c) => c.classList.remove("collapsed"));
    } else {
      applyCollapsed();
      applyAccordion();
    }

    $$("#sections [data-search]").forEach((el) => {
      const match = !searching || tokens.every((t) => el.dataset.search.indexOf(t) !== -1);
      el.classList.toggle("hidden", !match);
    });

    $$("#sections .group").forEach((g) => {
      g.classList.toggle("hidden", searching && !g.querySelector("[data-search]:not(.hidden)"));
    });

    let any = false;
    $$(".cat-section").forEach((s) => {
      const has = s.querySelector(".group:not(.hidden)");
      s.classList.toggle("hidden", searching && !has);
      if (has) any = true;
    });

    $$(".nav-link").forEach((l) => {
      const sec = document.getElementById(l.dataset.target);
      const grp = sec && sec.querySelector('.group[data-group="' + l.dataset.group + '"]');
      const vis = grp && !grp.classList.contains("hidden");
      l.classList.toggle("hidden", searching && !vis);
    });
    $$(".nav-cat").forEach((c) => {
      c.classList.toggle("hidden", searching && !c.querySelector(".nav-link:not(.hidden)"));
    });

    $("#noResults").hidden = !(searching && !any);
  }

  function clearSearch() {
    const s = $("#search");
    s.value = "";
    runSearch("");
  }

  function initSearch() {
    const s = $("#search");
    s.addEventListener("input", () => runSearch(s.value));
    $("#searchClear").addEventListener("click", () => { clearSearch(); s.focus(); });
  }

  function focusSearch() {
    const s = $("#search");
    s.focus();
    s.select();
  }

  function initKeyboard() {
    document.addEventListener("keydown", (e) => {
      const t = e.target;
      const tag = (t.tagName || "").toLowerCase();
      const typing = tag === "input" || tag === "textarea" || tag === "select" || t.isContentEditable;

      if ((e.key === "k" || e.key === "K") && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        focusSearch();
      } else if (e.key === "/" && !typing) {
        e.preventDefault();
        focusSearch();
      } else if (e.key === "Escape" && t.id === "search") {
        clearSearch();
        t.blur();
      }
    });

    if (/Mac|iPhone|iPad/.test(navigator.platform)) {
      const hint = $("#searchHint");
      if (hint) hint.textContent = "⌘K";
    }
  }

  function initChrome() {
    window.addEventListener("scroll", () => {
      document.body.classList.toggle("scrolled", window.scrollY > 4);
    }, { passive: true });
  }

  function initMobile() {
    const btn = $("#menuToggle");
    if (btn) btn.addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  }

  /* ---------- shared namespace ---------- */
  window.CTF = { $, $$, toast, esc, copyText, ICONS };

  document.addEventListener("DOMContentLoaded", () => {
    renderSidebar();
    renderSections();
    applyCollapsed();
    renderQuickAccess();
    setActive(STORE.get("ctf.activeCat", CTF_DATA[0].id), false);
    initScrollSpy();
    initTargetPanel();
    initSearch();
    initKeyboard();
    initMobile();
    initChrome();
  });
})();
