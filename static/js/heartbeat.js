// Polling del estado del PC con GPU (worker remoto del extractor RAG).
// El servidor expone /api/demo/pc_status devolviendo:
//   { online: bool, last_seen_iso: str|null, seconds_since: number|null, hostname: str|null }

(function () {
  const POLL_MS = 5000;
  const indicator = document.getElementById("pc-indicator");
  const label = document.getElementById("pc-status-label");
  if (!indicator || !label) return;

  function setStatus(state, text, title) {
    indicator.dataset.status = state;
    label.textContent = text;
    if (title) indicator.setAttribute("title", title);
  }

  function fmtAgo(s) {
    if (s == null) return "";
    if (s < 60) return `${Math.round(s)}s`;
    if (s < 3600) return `${Math.round(s / 60)}m`;
    return `${Math.round(s / 3600)}h`;
  }

  async function tick() {
    try {
      const r = await fetch("/api/demo/pc_status", { cache: "no-store" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = await r.json();
      if (data.online) {
        setStatus(
          "online",
          data.hostname ? `online · ${data.hostname}` : "online",
          `Último heartbeat hace ${fmtAgo(data.seconds_since)}`
        );
      } else {
        const ago = data.last_seen_iso
          ? `último contacto hace ${fmtAgo(data.seconds_since)}`
          : "sin contacto previo";
        setStatus("offline", "offline", ago);
      }
    } catch (err) {
      setStatus("error", "error", String(err));
    }
  }

  tick();
  setInterval(tick, POLL_MS);
})();
