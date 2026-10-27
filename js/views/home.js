// Vista Inicio: saludo, llamada a pedir, novedades, top, cifras y cómo funciona.
import { auth, countPublicRequests } from "../api.js";
import { esc, icon } from "../dom.js";
import { store, loadSongs, onSongsChange, sortSongs, topStyles } from "../store.js";
import { songCard, songRow, cardSkeleton, rowSkeleton, emptyState } from "../song-ui.js";
import { syncSongEls } from "../player.js";
import { DISCORD_URL } from "../config.js";

let requestsCache = null; // { total, capped } — se calcula una vez por sesión

function greeting() {
  const h = new Date().getHours();
  if (h >= 6 && h < 13) return "Buenos días";
  if (h >= 13 && h < 21) return "Buenas tardes";
  return "Buenas noches";
}

const stat = (id, label) => `
  <div class="stat"><div class="stat__label">${label}</div><div class="stat__value" id="${id}">—</div></div>`;

export const homeView = {
  title: "Inicio",
  async mount(root) {
    const user = auth.user();
    root.innerHTML = `
      <header class="view-head">
        <p class="t-kicker">${greeting()}</p>
        <h1 class="t-h1">${user ? "@" + esc(user) : "BeefMusic"}</h1>
      </header>

      <section class="hero-card" aria-labelledby="hero-title">
        <div class="t-kicker" style="color:var(--text)">Taller de temas a la carta</div>
        <h2 class="t-display" id="hero-title">Tu historia, hecha tema</h2>
        <p class="t-body hero-card__text">Tú escribes la movida, la petición entra en el <strong>Discord</strong> y vuelve convertida en canción lista para escuchar y compartir.</p>
        <div class="hero-card__cta">
          <button class="btn btn--primary" data-action="pedir">${icon("plus", "icon--sm")}Pedir canción</button>
          <a class="btn btn--outline" href="#/peticiones">Peticiones en curso</a>
        </div>
        <p class="hero-card__meta t-meta"><span class="text-beef tabular" id="hero-requests">—</span> peticiones registradas · <span id="hero-styles">Drill, trap, dembow, boom bap y lo que se venga</span></p>
      </section>

      <section class="section" aria-labelledby="new-title">
        <div class="section__head">
          <h2 class="t-h2" id="new-title">Novedades</h2>
          <a class="section__link" href="#/canciones">Ver todo</a>
        </div>
        <div class="shelf shelf--scroll" id="home-new" data-queue>${cardSkeleton(6)}</div>
      </section>

      <div class="home-split">
        <section class="section" aria-labelledby="top-title">
          <div class="section__head">
            <h2 class="t-h2" id="top-title">Lo más votado</h2>
            <a class="section__link" href="#/canciones?orden=top">Ver top</a>
          </div>
          <div class="list" id="home-top" data-queue>${rowSkeleton(5)}</div>
        </section>

        <section class="section" aria-labelledby="stats-title">
          <div class="section__head"><h2 class="t-h2" id="stats-title">Cómo se mueve BeefMusic</h2></div>
          <div class="stats">
            ${stat("stat-songs", "Canciones")}
            ${stat("stat-requests", "Peticiones")}
            ${stat("stat-people", "Gente implicada")}
            ${stat("stat-genres", "Estilos")}
          </div>
        </section>
      </div>

      <section class="section" aria-labelledby="how-title">
        <div class="section__head"><h2 class="t-h2" id="how-title">De lo que cuentas al tema final</h2></div>
        <ol class="steps">
          <li class="step"><span class="step__n">01</span><div><h3 class="t-h3">Manda la historia</h3><p class="t-meta">Nombres, detalles, frases que quieras que salgan y el estilo. Llega a un canal privado del Discord.</p></div></li>
          <li class="step"><span class="step__n">02</span><div><h3 class="t-h3">Se cocina en Discord</h3><p class="t-meta">Se revisa la petición, se monta el beat, se escribe la letra y se ajusta hasta que suena como tiene que sonar.</p></div></li>
          <li class="step"><span class="step__n">03</span><div><h3 class="t-h3">Sale a la luz</h3><p class="t-meta">El tema se sube a BeefMusic para escucharlo, votarlo, comentarlo y compartirlo.</p></div></li>
        </ol>
      </section>

      <section class="section">
        <a class="discord-card" href="${DISCORD_URL}" target="_blank" rel="noopener">
          <div>
            <div class="t-kicker">Comunidad</div>
            <div class="t-h3" style="margin-top:4px">Tu petición acaba en el Discord y vuelve hecha canción</div>
            <p class="t-meta" style="margin-top:4px">Únete al servidor para seguir cómo se trabaja cada tema.</p>
          </div>
          <span class="btn btn--sm">Unirme ${icon("external", "icon--sm")}</span>
        </a>
      </section>
    `;

    const paint = () => {
      const newEl = root.querySelector("#home-new");
      const topEl = root.querySelector("#home-top");
      if (!newEl) return;
      if (store.error && !store.loaded) {
        const retry = `<button class="btn btn--sm" data-action="reload-songs">Reintentar</button>`;
        newEl.innerHTML = emptyState("alert", "No se pudieron cargar las canciones", "El servidor puede tardar unos segundos en despertar.", retry);
        topEl.innerHTML = "";
        return;
      }
      if (!store.loaded) return;
      const songs = store.songs;
      if (!songs.length) {
        newEl.innerHTML = emptyState("music", "Aún no hay canciones", "Cuando se publique la primera, saldrá aquí.");
        topEl.innerHTML = "";
      } else {
        newEl.innerHTML = sortSongs(songs, "recientes").slice(0, 10).map(songCard).join("");
        topEl.innerHTML = sortSongs(songs, "top").slice(0, 5).map((s, i) => songRow(s, i + 1)).join("");
      }

      const styles = new Set(songs.map((s) => s.estilo.toLowerCase()).filter(Boolean));
      const people = new Set(songs.map((s) => s.autor.toLowerCase()).filter(Boolean));
      setText(root, "#stat-songs", songs.length);
      setText(root, "#stat-genres", styles.size);
      setText(root, "#stat-people", people.size);
      const pretty = topStyles(5);
      if (pretty.length) setText(root, "#hero-styles", pretty.join(", ") + (styles.size > pretty.length ? " y más" : ""));
      syncSongEls(root);
    };

    const off = onSongsChange(paint);
    paint();
    loadSongs().catch(() => {});

    paintRequests(root);
    return off;
  },
};

function setText(root, sel, value) {
  const el = root.querySelector(sel);
  if (el) el.textContent = String(value);
}

async function paintRequests(root) {
  try {
    if (!requestsCache) requestsCache = await countPublicRequests();
    const label = requestsCache.capped ? `${requestsCache.total}+` : String(requestsCache.total);
    setText(root, "#stat-requests", label);
    setText(root, "#hero-requests", label);
  } catch {
    setText(root, "#stat-requests", "—");
  }
}

// Para refrescar el contador tras enviar una petición.
export function invalidateRequestsCount() {
  requestsCache = null;
}
