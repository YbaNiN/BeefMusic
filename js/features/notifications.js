// Campana de notificaciones: contador, hoja con la lista y consulta cada 45 s.
import { auth, notificationsApi } from "../api.js";
import { $, $$, esc, icon, timeAgo } from "../dom.js";
import { openSheet } from "../sheets.js";

let lastServerTime = null;
let unread = 0;

function paintBadge() {
  $$("[data-notif-badge]").forEach((b) => {
    b.hidden = unread <= 0;
    b.textContent = unread > 99 ? "99+" : String(unread);
  });
  $$("[data-action='notifs']").forEach((btn) =>
    btn.setAttribute("aria-label", unread > 0 ? `Notificaciones, ${unread} sin leer` : "Notificaciones")
  );
}

function render(items) {
  const list = $("#notifs-list");
  if (!items || !items.length) {
    list.innerHTML = `<div class="empty">${icon("bell")}<div class="t-ui" style="color:var(--text)">No tienes notificaciones</div><div class="t-meta">Te avisaremos cuando tus peticiones avancen o te respondan.</div></div>`;
    return;
  }
  list.innerHTML = items
    .map(
      (n) => `
      <button class="notif${n.read_at ? " notif--read" : ""}" data-id="${esc(n.id)}" data-link="${esc(n.link_url || "")}">
        <span class="notif__dot" aria-hidden="true"></span>
        <span class="notif__text">
          <span class="t-ui notif__title">${esc(n.title || "")}</span>
          ${n.body ? `<span class="t-meta notif__body">${esc(n.body)}</span>` : ""}
          <span class="t-caption">${esc(timeAgo(n.created_at))}</span>
        </span>
        ${n.link_url ? icon("chevron-right", "icon--sm") : ""}
      </button>`
    )
    .join("");
}

async function refresh({ withList = false } = {}) {
  if (!auth.isLogged()) return;
  const params = { limit: "15", offset: "0" };
  if (lastServerTime) params.after = lastServerTime;
  const data = await notificationsApi.list(params);
  unread = data.unreadCount || 0;
  paintBadge();
  const hasNew = Array.isArray(data.items) && data.items.length > 0;
  if (withList || hasNew || $("#sheet-notifs").open) {
    const full = await notificationsApi.list({ limit: "30", offset: "0" });
    render(full.items || []);
  }
  lastServerTime = data.serverTime || new Date().toISOString();
}

// Los enlaces antiguos (canciones.html?song=X, peticiones.html…) se abren
// dentro de la app, así la música no se corta.
function openLink(link) {
  if (!link) return;
  try {
    const url = new URL(link, location.href);
    const page = url.origin === location.origin ? (url.pathname.match(/\/(canciones|peticiones|comunidad|perfil)\.html$/) || [])[1] : null;
    if (page) {
      $("#sheet-notifs").close();
      if (page === "canciones") {
        const song = url.searchParams.get("song");
        location.hash = "#/canciones" + (song ? "?song=" + encodeURIComponent(song) : "");
      } else if (page === "comunidad" && url.searchParams.get("u")) {
        location.hash = "#/u/" + encodeURIComponent(url.searchParams.get("u"));
      } else {
        location.hash = "#/" + page;
      }
      return;
    }
    location.href = url.toString();
  } catch {
    location.href = link;
  }
}

export function openNotifications() {
  openSheet("sheet-notifs");
  $("#notifs-list").innerHTML = `<div class="empty"><span class="spinner" aria-hidden="true"></span><div class="t-meta">Cargando…</div></div>`;
  refresh({ withList: true }).catch(() => render([]));
}

export function initNotifications() {
  if (!auth.isLogged()) return;

  $("#notifs-readall").addEventListener("click", async () => {
    try {
      await notificationsApi.readAll();
    } catch {
      /* se reintenta con el siguiente refresco */
    }
    refresh({ withList: true }).catch(() => {});
  });

  $("#notifs-list").addEventListener("click", async (e) => {
    const item = e.target.closest(".notif");
    if (!item) return;
    try {
      await notificationsApi.read(item.dataset.id);
    } catch {
      /* no bloquea la navegación */
    }
    refresh({ withList: true }).catch(() => {});
    openLink(item.dataset.link);
  });

  refresh().catch(() => {});
  setInterval(() => {
    if (document.visibilityState === "visible") refresh().catch(() => {});
  }, 45000);
}
