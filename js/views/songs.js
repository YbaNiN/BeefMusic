// Vista Canciones: buscar, filtrar por estilo, ordenar, reproducir y votar.
import { $$, esc, icon, debounce } from "../dom.js";
import { store, loadSongs, onSongsChange, sortSongs, topStyles } from "../store.js";
import { songRow, rowSkeleton, emptyState } from "../song-ui.js";
import { player, syncSongEls } from "../player.js";
import { openSongSheet } from "../song-sheet.js";

// Se conserva al cambiar de sección y volver.
const state = { q: "", genre: "", sort: "recientes" };

function filtered() {
  const q = state.q.toLowerCase();
  const g = state.genre.toLowerCase();
  const list = store.songs.filter((s) => {
    const text = `${s.titulo} ${s.autor} ${s.estilo} ${s.descripcion}`.toLowerCase();
    return (!q || text.includes(q)) && (!g || s.estilo.toLowerCase().includes(g));
  });
  return sortSongs(list, state.sort);
}

export const songsView = {
  title: "Canciones",
  async mount(root, params) {
    if (params.orden === "top") state.sort = "top";

    root.innerHTML = `
      <header class="view-head view-head--row">
        <div>
          <p class="t-kicker">Colección BeefMusic</p>
          <h1 class="t-h1">Canciones</h1>
          <p class="t-meta tabular" id="songs-count" aria-live="polite" style="margin-top:4px">Cargando…</p>
        </div>
        <button class="play play--lg" id="play-all" aria-label="Reproducir la lista" disabled>
          ${icon("play", "icon--fill i-play")}${icon("pause", "icon--fill i-pause")}
        </button>
      </header>

      <div class="songs-tools">
        <label class="search">
          ${icon("search", "icon--sm")}
          <span class="sr-only">Buscar canciones</span>
          <input id="songs-search" type="search" value="${esc(state.q)}" placeholder="Título, autor, estilo o historia" autocomplete="off" enterkeyhint="search" />
        </label>
        <div class="songs-tools__row">
          <div class="chips" id="genre-chips" role="group" aria-label="Filtrar por estilo"></div>
          <div class="segmented" role="tablist" aria-label="Orden">
            <button role="tab" data-sort="recientes" aria-selected="${state.sort === "recientes"}">Recientes</button>
            <button role="tab" data-sort="top" aria-selected="${state.sort === "top"}">${icon("flame", "icon--sm")}Top</button>
          </div>
        </div>
      </div>

      <div class="list" id="songs-list" data-queue>${rowSkeleton(8)}</div>
    `;

    const listEl = root.querySelector("#songs-list");
    const countEl = root.querySelector("#songs-count");
    const chipsEl = root.querySelector("#genre-chips");
    const search = root.querySelector("#songs-search");
    const playAll = root.querySelector("#play-all");

    const paintChips = () => {
      const styles = topStyles(6);
      if (state.genre && !styles.some((s) => s.toLowerCase() === state.genre.toLowerCase())) styles.unshift(state.genre);
      chipsEl.innerHTML = [`<button class="chip" data-genre="" aria-pressed="${!state.genre}">Todo</button>`]
        .concat(styles.map((s) => `<button class="chip" data-genre="${esc(s)}" aria-pressed="${state.genre.toLowerCase() === s.toLowerCase()}">${esc(s)}</button>`))
        .join("");
    };

    const paintPlayAll = () => {
      const list = filtered();
      const inList = list.some((s) => player.isCurrent(s.id));
      playAll.disabled = !list.some((s) => s.url);
      playAll.classList.toggle("is-playing", inList && player.isPlaying());
      playAll.setAttribute("aria-label", inList && player.isPlaying() ? "Pausar" : "Reproducir la lista");
    };

    const paint = () => {
      if (store.error && !store.loaded) {
        countEl.textContent = "";
        listEl.innerHTML = emptyState("alert", "No se pudieron cargar las canciones", "El servidor puede tardar unos segundos en despertar.", `<button class="btn btn--sm" data-action="reload-songs">Reintentar</button>`);
        return;
      }
      if (!store.loaded) return;
      const list = filtered();
      countEl.textContent = `${list.length} ${list.length === 1 ? "tema" : "temas"}`;
      listEl.innerHTML = list.length
        ? list.map((s, i) => songRow(s, i + 1)).join("")
        : store.songs.length
          ? emptyState("search", "Nada con ese filtro", "Prueba con otro estilo o con otra búsqueda.", `<button class="btn btn--sm" data-clear-filters>Quitar filtros</button>`)
          : emptyState("music", "Todavía no hay canciones publicadas", "Cuando se publique la primera, se verá aquí.");
      syncSongEls(listEl);
      paintPlayAll();
    };

    search.addEventListener("input", debounce(() => { state.q = search.value.trim(); paint(); }, 120));
    chipsEl.addEventListener("click", (e) => {
      const chip = e.target.closest("[data-genre]");
      if (!chip) return;
      state.genre = chip.dataset.genre;
      $$("[data-genre]", chipsEl).forEach((c) => c.setAttribute("aria-pressed", String(c === chip)));
      paint();
    });
    root.querySelectorAll("[data-sort]").forEach((b) =>
      b.addEventListener("click", () => {
        state.sort = b.dataset.sort;
        root.querySelectorAll("[data-sort]").forEach((o) => o.setAttribute("aria-selected", String(o === b)));
        paint();
      })
    );
    root.addEventListener("click", (e) => {
      if (!e.target.closest("[data-clear-filters]")) return;
      state.q = "";
      state.genre = "";
      search.value = "";
      paintChips();
      paint();
    });
    playAll.addEventListener("click", () => {
      const list = filtered();
      const current = list.find((s) => player.isCurrent(s.id));
      if (current) return player.toggle();
      const first = list.find((s) => s.url);
      if (first) player.playFrom(list, first.id);
    });

    const offSongs = onSongsChange((_, changedId) => {
      // Un voto solo cambia el orden en "Top"; en "Recientes" basta con repintar la lista.
      if (changedId != null || store.loaded) paintChips();
      paint();
    });
    const onAudio = () => paintPlayAll();
    player.audio.addEventListener("play", onAudio);
    player.audio.addEventListener("pause", onAudio);

    paint();
    if (params.buscar) requestAnimationFrame(() => search.focus());

    loadSongs()
      .then(() => {
        paintChips();
        paint();
        if (params.song) openSongSheet(params.song);
      })
      .catch(() => {});

    return () => {
      offSongs();
      player.audio.removeEventListener("play", onAudio);
      player.audio.removeEventListener("pause", onAudio);
    };
  },

  update(params) {
    if (params.song) loadSongs().then(() => openSongSheet(params.song)).catch(() => {});
    if (params.buscar) document.getElementById("songs-search")?.focus();
  },
};
