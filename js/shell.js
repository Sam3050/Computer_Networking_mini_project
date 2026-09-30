/* ============================================================
   SHELL — renders the sidebar + topbar shell on every page.
   Keeps nav markup in one place instead of duplicating per page.
   ============================================================ */

(function () {
  const NAV = [
    { href: "index.html", key: "dashboard", label: "Dashboard", icon: "grid" },
    { href: "scan.html", key: "scan", label: "New Scan", icon: "radar" },
    { href: "report.html", key: "report", label: "Reports", icon: "doc" },
    { href: "about.html", key: "about", label: "Methodology", icon: "book" },
  ];

  const ICONS = {
    grid: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
    radar: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none"/><path d="M12 12 L18 7"/></svg>',
    doc: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M6 2h9l5 5v15H6z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h6"/></svg>',
    book: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 5c2-1.3 5-1.3 8 0v14c-3-1.3-6-1.3-8 0z"/><path d="M20 5c-2-1.3-5-1.3-8 0v14c3-1.3 6-1.3 8 0z"/></svg>',
  };

  function mark() {
    return `<svg class="sidebar__mark" viewBox="0 0 32 32" fill="none">
      <circle cx="16" cy="16" r="14" stroke="#E8A33D" stroke-width="1.4" opacity="0.5"/>
      <circle cx="16" cy="16" r="9" stroke="#E8A33D" stroke-width="1.4" opacity="0.75"/>
      <circle cx="16" cy="16" r="2.2" fill="#E8A33D"/>
      <path d="M16 16 L23 9" stroke="#E8A33D" stroke-width="1.6" stroke-linecap="round"/>
    </svg>`;
  }

  function render(activeKey, crumb) {
    const nav = NAV.map(
      (item) => `<a class="navlink${item.key === activeKey ? " is-active" : ""}" href="${item.href}">${ICONS[item.icon]}<span>${item.label}</span></a>`
    ).join("");

    document.body.insertAdjacentHTML(
      "afterbegin",
      `<div class="app">
        <aside class="sidebar">
          <div class="sidebar__brand">
            ${mark()}
            <div class="sidebar__brand-text">
              <span class="sidebar__brand-name">Sentry&nbsp;Sweep</span>
              <span class="sidebar__brand-sub">NET-VULN ANALYSIS</span>
            </div>
          </div>
          <nav class="sidebar__nav">
            <div class="sidebar__label">WORKSPACE</div>
            ${nav}
          </nav>
          <div class="sidebar__foot">
            <div class="sidebar__status"><span class="dot"></span> Engine ready · v1.0</div>
          </div>
        </aside>
        <div class="main">
          <div class="topbar">
            <div class="topbar__crumb">Sentry Sweep / <b>${crumb}</b></div>
            <div class="topbar__crumb" id="clock"></div>
          </div>
          <main class="content" id="content"></main>
        </div>
      </div>`
    );

    const clock = document.getElementById("clock");
    const tick = () => {
      clock.textContent = new Date().toLocaleString("en-US", {
        weekday: "short", month: "short", day: "numeric",
        hour: "2-digit", minute: "2-digit",
      });
    };
    tick();
    setInterval(tick, 30000);
  }

  window.Shell = { render };
})();
