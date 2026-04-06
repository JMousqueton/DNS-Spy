/* DNS Spy — Client-side JS */

(function () {
  "use strict";

  /* ── Theme toggle ───────────────────────────────────────── */
  const THEME_KEY = "dns-spy-theme";

  function getTheme() {
    return localStorage.getItem(THEME_KEY) ||
      (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    document.querySelectorAll(".theme-toggle").forEach((btn) => {
      btn.innerHTML = theme === "dark"
        ? '<i class="fa-solid fa-sun"></i>'
        : '<i class="fa-solid fa-moon"></i>';
      btn.setAttribute("aria-label", theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
    });
  }

  function toggleTheme() {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
  }

  // Apply saved theme immediately (before paint)
  applyTheme(getTheme());

  // Wire up all toggle buttons (added by templates)
  document.addEventListener("click", (e) => {
    if (e.target.closest(".theme-toggle")) toggleTheme();
  });

  /* ── Loading overlay on form submit ────────────────────── */
  function attachLoadingOverlay(form) {
    form.addEventListener("submit", function () {
      const domainInput = form.querySelector('input[name="domain"]');
      const domain = domainInput ? domainInput.value.trim() : "";
      if (!domain) return;

      const overlay = document.createElement("div");
      overlay.className = "loading-overlay";
      overlay.setAttribute("role", "status");
      overlay.setAttribute("aria-live", "polite");
      overlay.innerHTML = `
        <div class="spinner" aria-hidden="true"></div>
        <div class="loading-text">
          Analyzing <span class="loading-domain">${escapeHtml(domain)}</span>&hellip;
        </div>
        <div class="loading-text" style="font-size:0.82rem;opacity:0.6;">Running all lookups in parallel</div>
      `;
      document.body.appendChild(overlay);
    });
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  document.querySelectorAll("form").forEach(attachLoadingOverlay);

  /* ── Smooth active TOC link highlight ──────────────────── */
  function initTocHighlight() {
    const toc = document.querySelector(".toc");
    if (!toc) return;

    const sections = Array.from(document.querySelectorAll(".card[id]"));
    const links = Array.from(toc.querySelectorAll("a"));
    if (!sections.length || !links.length) return;

    function activate(id) {
      links.forEach((link) => {
        const active = link.getAttribute("href") === "#" + id;
        link.classList.toggle("active", active);
      });
    }

    function onScroll() {
      const scrollBottom = window.scrollY + window.innerHeight;
      const pageHeight = document.documentElement.scrollHeight;

      // At the bottom of the page → always highlight the last section
      if (scrollBottom >= pageHeight - 4) {
        activate(sections[sections.length - 1].id);
        return;
      }

      // Find the last section whose top is above the top third of the viewport
      const threshold = window.scrollY + window.innerHeight * 0.3;
      let active = sections[0];
      for (const section of sections) {
        if (section.offsetTop <= threshold) {
          active = section;
        }
      }
      activate(active.id);
    }

    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll(); // set initial state
  }

  initTocHighlight();

  /* ── Collapsible raw headers ────────────────────────────── */
  function initCollapsibles() {
    const headersRaw = document.querySelector(".headers-raw");
    if (!headersRaw) return;

    const wrapper = headersRaw.parentElement;
    const toggle = document.createElement("button");
    toggle.textContent = "Show all headers";
    toggle.style.cssText =
      "background:none;border:1px solid var(--border);color:var(--accent);border-radius:4px;padding:0.25rem 0.6rem;font-size:0.8rem;cursor:pointer;margin-bottom:0.5rem;";
    headersRaw.style.display = "none";

    toggle.addEventListener("click", () => {
      const hidden = headersRaw.style.display === "none";
      headersRaw.style.display = hidden ? "block" : "none";
      toggle.textContent = hidden ? "Hide headers" : "Show all headers";
    });

    wrapper.insertBefore(toggle, headersRaw);
  }

  initCollapsibles();

  /* ── Smart URL stripping on domain inputs ───────────────── */
  // Accepts full URLs like https://github.com/foo/bar → github.com
  function extractHostname(val) {
    val = val.trim();
    if (!val) return val;
    // If it contains a scheme or looks like a URL path, parse it
    if (val.includes("://") || val.startsWith("//")) {
      try {
        const url = new URL(val.startsWith("//") ? "http:" + val : val);
        return url.hostname;
      } catch (_) {}
    }
    // Bare domain: strip scheme prefix, path, port
    return val
      .replace(/^https?:\/\//, "")
      .split("/")[0]
      .split("?")[0]
      .split("#")[0]
      .replace(/:\d+$/, "");
  }

  document.querySelectorAll('input[name="domain"]').forEach((input) => {
    input.addEventListener("blur", () => {
      const cleaned = extractHostname(input.value);
      if (cleaned) input.value = cleaned;
    });
  });

  /* ── Active TOC style ───────────────────────────────────── */
  const style = document.createElement("style");
  style.textContent = ".toc a.active { color: var(--accent); background: var(--bg-hover); }";
  document.head.appendChild(style);

  /* ── About modal ────────────────────────────────────────── */
  const modal = document.getElementById("aboutModal");
  if (modal) {
    function openModal() { modal.classList.add("open"); }
    function closeModal() { modal.classList.remove("open"); }

    // Open triggers: topnav icon + footer link
    document.querySelectorAll("#aboutBtn, #aboutBtnFooter").forEach((btn) => {
      btn.addEventListener("click", openModal);
    });

    // Close triggers: X button, backdrop click, Escape key
    document.getElementById("aboutClose")?.addEventListener("click", closeModal);
    modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  }
})();
