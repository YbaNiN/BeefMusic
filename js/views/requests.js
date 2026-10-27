// Vista Peticiones en curso: listado público con filtros de estado, estilo y nick.
import { publicRequests } from "../api.js";
import { esc, icon, timeAgo } from "../dom.js";
import { emptyState } from "../song-ui.js";
import { replaceParams } from "../router.js";

const LIMIT = 24;
const ESTADOS = [
  ["", "Todas"],
  ["pendiente", "Pendientes"],
  ["en_produccion", "En producción"],
  ["terminada", "Terminadas"],
];
const ESTADO_UI = {
  pendiente: ["status--pendiente", "Pendiente"],
  en_produccion: ["status--produccion", "En producción"],
  terminada: ["status--terminada", "Terminada"],
};

let knownStyles = null; // estilos vistos en las últimas peticiones (para los filtros)

const cap = (s) => String(s || "").charAt(0).toUpperCase() + String(s || "").slice(1);

function requestRow(p) {
  const estilo = (p.estilo || "").trim() || "Sin estilo";
  const [cls, label] = ESTADO_UI[p.estado] || ["", "Desconocido"];
  const nick = p.nick && String(p.nick).trim() ? String(p.nick).trim().replace(/^@/, "") : "";
  const date = p.created_at ? new Date(p.created_at) : null;
  const when = date && !Number.isNaN(date.getTime())
    ? `<time datetime="${esc(date.toISOString())}" title="${esc(date.toLocaleString("es-ES"))}">${esc(timeAgo(p.created_at))}</time>`
    : "";
  return `
    <article class="row req">
      ${window.BeefCover.html({ id: "req" + p.id, titulo: estilo, estilo })}
      <div class="row__body">
        <div class="req__title"><span class="row__title clamp-1">${esc(cap(estilo))}</span><span class="req__id tabular">#${esc(p.id)}</span></div>
        <div class="row__meta req__meta">
          ${nick ? `<span class="clamp-1">@${esc(nick)}</span>` : `<span class="req__anon">${icon("lock", "icon--sm")}Anónimo</span>`}
          ${when ? `<span aria-hidden="true">·</span>${when}` : ""}
        </div>
      </div>
      <span class="status ${cls}">${esc(label)}</span>
    </article>`;
}

async function loadKnownStyles() {
  if (knownStyles) return knownStyles;
  try {
    const data = await publicRequests({ limit: 100, offset: 0 });
    // "dembow" y "Dembow" son el mismo chip; el filtro usa la variante más usada
    // porque el backend compara el texto exacto.
    const byKey = new Map();
    (Array.isArray(data) ? data : []).forEach((p) => {
      const e = (p.estilo || "").trim();
      if (!e) return;
      const key = e.toLowerCase();
      const entry = byKey.get(key) || { total: 0, variants: new Map() };
      entry.total++;
      entry.variants.set(e, (entry.variants.get(e) || 0) + 1);
      byKey.set(key, entry);
    });
    knownStyles = [...byKey.values()]
      .sort((a, b) => b.total - a.total)
      .slice(0, 10)
      .map((x) => [...x.variants.entries()].sort((a, b) => b[1] - a[1])[0][0]);
  } catch {
    knownStyles = [];
  }
  return knownStyles;
}

export const requestsView = {
  title: "Peticiones",
  nav: "peticiones",
  mount(root, params) {
    const f = { estado: "", estilo: "", nick: false };
    const fromParams = (p) => {
      f.estado = ESTADOS.some(([k]) => k === p.estado) ? p.estado : "";
      f.estilo = (p.estilo || "").trim();
      f.nick = p.nick === "1";
    };
    fromParams(params);

    root.innerHTML = `
      <header class="view-head view-head--row">
        <div>
          <p class="t-kicker">Transparencia</p>
          <h1 class="t-h1">Peticiones en curso</h1>
          <p class="t-meta tabular" id="req-count" aria-live="polite" style="margin-top:4px">Cargando…</p>
        </div>
        <button class="btn btn--primary" data-action="pedir">${icon("plus", "icon--sm")}Pedir</button>
      </header>
      <p class="t-meta req-note">Aquí ves en qué punto está cada petición, sin enseñar lo que se ha pedido. El nick solo aparece si la persona lo ha aceptado.</p>

      <div class="req-tools">
        <div class="chips" id="req-estado" role="group" aria-label="Filtrar por estado"></div>
        <div class="chips" id="req-estilo" role="group" aria-label="Filtrar por estilo"></div>
        <div class="req-tools__row">
          <label class="switch-inline" for="req-nick">
            <input type="checkbox" class="switch switch--sm" id="req-nick" role="switch" />
            <span class="t-meta">Solo con nick visible</span>
          </label>
          <button class="btn btn--ghost btn--sm" id="req-clear" hidden>Quitar filtros</button>
        </div>
      </div>

      <div class="list" id="req-list"></div>
      <button class="btn btn--outline btn--block" id="req-more" hidden>Cargar más</button>
    `;

    const list = root.querySelector("#req-list");
    const more = root.querySelector("#req-more");
    const count = root.querySelector("#req-count");
    const estadoEl = root.querySelector("#req-estado");
    const estiloEl = root.querySelector("#req-estilo");
    const nickEl = root.querySelector("#req-nick");
    const clearEl = root.querySelector("#req-clear");

    let offset = 0;
    let shown = 0;
    let hasMore = false;
    let token = 0; // descarta respuestas de filtros anteriores

    const paintFilters = () => {
      estadoEl.innerHTML = ESTADOS.map(([k, label]) => {
        const dot = k ? `<span class="chip__dot ${ESTADO_UI[k][0]}" aria-hidden="true"></span>` : "";
        return `<button class="chip" data-estado="${k}" aria-pressed="${f.estado === k}">${dot}${label}</button>`;
      }).join("");
      const styles = [...(knownStyles || [])];
      if (f.estilo && !styles.some((s) => s.toLowerCase() === f.estilo.toLowerCase())) styles.unshift(f.estilo);
      estiloEl.innerHTML = [`<button class="chip" data-estilo="" aria-pressed="${!f.estilo}">Cualquier estilo</button>`]
        .concat(styles.map((s) => `<button class="chip" data-estilo="${esc(s)}" aria-pressed="${f.estilo === s}">${esc(cap(s))}</button>`))
        .join("");
      nickEl.checked = f.nick;
      clearEl.hidden = !(f.estado || f.estilo || f.nick);
    };

    const syncUrl = () => {
      const p = {};
      if (f.estado) p.estado = f.estado;
      if (f.estilo) p.estilo = f.estilo;
      if (f.nick) p.nick = "1";
      replaceParams(p);
    };

    const paintCount = () => {
      count.textContent = shown
        ? `${shown}${hasMore ? "+" : ""} ${shown === 1 ? "petición" : "peticiones"}${f.estado || f.estilo || f.nick ? " con estos filtros" : ""}`
        : "";
    };

    async function load({ append = false } = {}) {
      const my = ++token;
      if (!append) {
        offset = 0;
        shown = 0;
        list.innerHTML = Array.from({ length: 6 }, () => `
          <div class="row req" aria-hidden="true"><div class="skel" style="width:48px;aspect-ratio:1"></div>
          <div style="display:grid;gap:6px"><div class="skel" style="height:12px;width:45%"></div><div class="skel" style="height:10px;width:30%"></div></div></div>`).join("");
        count.textContent = "Cargando…";
      }
      more.disabled = true;
      try {
        let added = 0;
        let tries = 0;
        let html = "";
        // Con "solo con nick" una página puede quedarse vacía: seguimos un poco más.
        do {
          const data = await publicRequests({ estado: f.estado, estilo: f.estilo, limit: LIMIT, offset });
          if (my !== token) return;
          const raw = Array.isArray(data) ? data : [];
          const items = f.nick ? raw.filter((p) => p.nick && String(p.nick).trim()) : raw;
          offset += LIMIT;
          hasMore = raw.length === LIMIT; // la versión antigua mostraba "más" aunque no quedaran
          html += items.map(requestRow).join("");
          added += items.length;
          tries++;
        } while (f.nick && added < 6 && hasMore && tries < 5);

        if (!append) list.innerHTML = "";
        list.insertAdjacentHTML("beforeend", html);
        shown += added;
        if (!shown) {
          list.innerHTML = emptyState("list", "No hay peticiones con estos filtros", "Prueba con otro estado o estilo, o pide tú la primera.", `<button class="btn btn--sm btn--primary" data-action="pedir">${icon("plus", "icon--sm")}Pedir canción</button>`);
        }
        more.hidden = !hasMore;
        paintCount();
      } catch (err) {
        if (my !== token) return;
        if (!append) {
          list.innerHTML = emptyState("alert", "No se pudieron cargar las peticiones", err.message, `<button class="btn btn--sm" id="req-retry">Reintentar</button>`);
          list.querySelector("#req-retry")?.addEventListener("click", () => load());
          count.textContent = "";
        } else {
          more.hidden = false;
        }
      } finally {
        if (my === token) more.disabled = false;
      }
    }

    const apply = () => {
      paintFilters();
      syncUrl();
      load();
    };

    estadoEl.addEventListener("click", (e) => {
      const b = e.target.closest("[data-estado]");
      if (!b) return;
      f.estado = b.dataset.estado;
      apply();
    });
    estiloEl.addEventListener("click", (e) => {
      const b = e.target.closest("[data-estilo]");
      if (!b) return;
      f.estilo = b.dataset.estilo;
      apply();
    });
    nickEl.addEventListener("change", () => {
      f.nick = nickEl.checked;
      apply();
    });
    clearEl.addEventListener("click", () => {
      Object.assign(f, { estado: "", estilo: "", nick: false });
      apply();
    });
    more.addEventListener("click", () => load({ append: true }));

    paintFilters();
    load();
    loadKnownStyles().then(() => {
      if (root.isConnected) paintFilters();
    });

    // Si la URL cambia desde fuera (p. ej. un enlace con filtros), se recargan.
    requestsView.update = (p) => {
      fromParams(p);
      paintFilters();
      load();
    };
    return () => {
      token++;
      requestsView.update = null;
    };
  },
  update: null,
};
