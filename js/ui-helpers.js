/* ============================================================
   UI HELPERS — small formatting/render utilities shared by pages
   ============================================================ */

(function () {
  function severityBadge(sev) {
    const labels = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO" };
    return `<span class="badge badge--${sev}">${labels[sev] || sev.toUpperCase()}</span>`;
  }

  function fmtDate(iso) {
    const d = new Date(iso);
    return d.toLocaleString("en-US", {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  window.UIHelpers = { severityBadge, fmtDate, escapeHtml };
})();
