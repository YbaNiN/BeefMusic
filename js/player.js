// Reproductor único de la app. Como la app es una sola página, este <audio>
// nunca se destruye y la música sigue al cambiar de sección.
import { $$, fmtTime, toast } from "./dom.js";
import { getSong, onSongsChange, vote } from "./store.js";
import { LAST_PLAYED_KEY } from "./config.js";

const audio = new Audio();
audio.preload = "metadata";

let queue = []; // ids de la lista desde la que se reprodujo
let index = -1;
let restoreAt = 0;
const listeners = new Set();

const currentId = () => (index >= 0 ? queue[index] : null);
const currentSong = () => (currentId() != null ? getSong(currentId()) : null);

export const player = {
  audio,
  currentSong,
  isCurrent: (id) => currentId() != null && String(currentId()) === String(id),
  isPlaying: () => !audio.paused && !audio.ended,
  onChange(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },

  // Reproduce `id` usando `list` (canciones) como cola.
  playFrom(list, id) {
    const playable = list.filter((s) => s.url);
    const ids = playable.map((s) => s.id);
    const i = ids.findIndex((x) => String(x) === String(id));
    if (i < 0) return toast("Esta canción aún no tiene audio", { error: true });
    if (this.isCurrent(id)) return this.toggle();
    queue = ids;
    index = i;
    start(true);
  },

  toggle() {
    if (index < 0) return;
    if (audio.paused) audio.play().catch(onPlayError);
    else audio.pause();
  },
  next() {
    if (!queue.length) return;
    index = (index + 1) % queue.length;
    start(true);
  },
  prev() {
    if (!queue.length) return;
    if (audio.currentTime > 3) {
      audio.currentTime = 0;
      return;
    }
    index = (index - 1 + queue.length) % queue.length;
    start(true);
  },

  // Recupera la última canción escuchada (en pausa), si sigue existiendo.
  restore(list) {
    if (index >= 0) return;
    let saved;
    try {
      saved = JSON.parse(localStorage.getItem(LAST_PLAYED_KEY) || "null");
    } catch {
      saved = null;
    }
    if (!saved) return;
    const playable = list.filter((s) => s.url);
    const i = playable.findIndex((s) => String(s.id) === String(saved.id));
    if (i < 0) return;
    queue = playable.map((s) => s.id);
    index = i;
    restoreAt = Number(saved.t) || 0;
    start(false);
  },
};

function onPlayError(err) {
  if (err && err.name === "AbortError") return;
  toast("No se pudo reproducir el audio", { error: true });
}

function start(autoplay) {
  const s = currentSong();
  if (!s) return;
  audio.src = s.url;
  if (autoplay) audio.play().catch(onPlayError);
  paintSong();
  save();
}

function save() {
  const s = currentSong();
  if (!s) return;
  try {
    localStorage.setItem(LAST_PLAYED_KEY, JSON.stringify({ id: s.id, t: Math.floor(audio.currentTime || restoreAt || 0) }));
  } catch {
    /* almacenamiento no disponible: no pasa nada */
  }
}

/* ---------------- Pintado de la interfaz ---------------- */
const els = (name) => $$(`[data-player="${name}"]`);

function paintSong() {
  const s = currentSong();
  const mini = document.getElementById("mini");
  if (!s) return;
  const spec = window.BeefCover.spec(s);
  els("cover").forEach((el) => {
    el.classList.remove("cover--empty");
    window.BeefCover.paint(el, s);
  });
  els("title").forEach((el) => (el.textContent = s.titulo));
  els("artist").forEach((el) => (el.textContent = "@" + s.autor + (s.estilo ? " · " + s.estilo : "")));
  document.documentElement.style.setProperty("--now-tint", spec.tint);
  if (mini) mini.hidden = false;
  $$("[data-player]").forEach((el) => {
    if (el.disabled !== undefined && el.dataset.player !== "vol") el.disabled = false;
  });
  paintVotes();
  paintTime();

  if ("mediaSession" in navigator) {
    navigator.mediaSession.metadata = new MediaMetadata({ title: s.titulo, artist: "@" + s.autor, album: "BeefMusic" });
  }
  listeners.forEach((fn) => fn());
}

function paintVotes() {
  const s = currentSong();
  if (!s) return;
  els("like").forEach((b) => b.setAttribute("aria-pressed", String(s.userVote === "like")));
  els("dislike").forEach((b) => b.setAttribute("aria-pressed", String(s.userVote === "dislike")));
  els("likes").forEach((el) => (el.textContent = s.likes));
}

function paintState() {
  const playing = player.isPlaying();
  els("toggle").forEach((b) => {
    b.classList.toggle("is-playing", playing);
    b.setAttribute("aria-label", playing ? "Pausar" : "Reproducir");
  });
  document.body.classList.toggle("has-playing", playing);
  syncSongEls();
  if ("mediaSession" in navigator) navigator.mediaSession.playbackState = playing ? "playing" : "paused";
}

function paintTime() {
  const d = audio.duration || 0;
  const p = d ? (audio.currentTime / d) * 100 : 0;
  els("cur").forEach((el) => (el.textContent = fmtTime(audio.currentTime)));
  els("dur").forEach((el) => (el.textContent = fmtTime(d)));
  els("seek").forEach((r) => {
    if (document.activeElement !== r) r.value = p;
    r.style.setProperty("--p", p + "%");
  });
  els("bar").forEach((b) => (b.style.width = p + "%"));
}

// Marca la canción que suena en cualquier lista o estantería visible.
export function syncSongEls(root = document) {
  const id = currentId();
  const playing = player.isPlaying();
  $$("[data-song]", root).forEach((el) => {
    const is = id != null && String(el.dataset.song) === String(id);
    el.classList.toggle("is-current", is);
    el.classList.toggle("is-playing", is && playing);
  });
}

/* ---------------- Eventos ---------------- */
let lastSave = 0;
audio.addEventListener("play", paintState);
audio.addEventListener("pause", () => {
  paintState();
  save();
});
audio.addEventListener("ended", () => player.next());
audio.addEventListener("loadedmetadata", () => {
  if (restoreAt && restoreAt < audio.duration - 2) audio.currentTime = restoreAt;
  restoreAt = 0;
  paintTime();
});
audio.addEventListener("timeupdate", () => {
  paintTime();
  if (Date.now() - lastSave > 5000) {
    lastSave = Date.now();
    save();
  }
});
audio.addEventListener("error", () => {
  if (audio.src) toast("No se pudo cargar el audio de esta canción", { error: true });
});

onSongsChange((_, changedId) => {
  if (changedId == null || player.isCurrent(changedId)) paintVotes();
});

export function initPlayerControls() {
  document.addEventListener("click", (e) => {
    const el = e.target.closest("[data-player]");
    if (!el || el.tagName === "INPUT") return;
    const action = el.dataset.player;
    const s = currentSong();
    if (["toggle", "next", "prev", "like", "dislike", "share"].includes(action)) e.stopPropagation();
    if (action === "toggle") player.toggle();
    else if (action === "next") player.next();
    else if (action === "prev") player.prev();
    else if ((action === "like" || action === "dislike") && s) vote(s.id, action);
    else if (action === "share" && s) shareSong(s);
  });

  $$('[data-player="seek"]').forEach((r) =>
    r.addEventListener("input", () => {
      r.style.setProperty("--p", r.value + "%");
      if (audio.duration) audio.currentTime = (r.value / 100) * audio.duration;
    })
  );
  const vol = document.querySelector('[data-player="vol"]');
  if (vol) {
    vol.addEventListener("input", () => {
      audio.volume = Number(vol.value);
      vol.style.setProperty("--p", vol.value * 100 + "%");
    });
  }

  // Espacio = play/pausa cuando no se está escribiendo.
  document.addEventListener("keydown", (e) => {
    if (e.code !== "Space" || index < 0) return;
    if (e.target.closest("input, textarea, button, [role='button'], select, [contenteditable]")) return;
    e.preventDefault();
    player.toggle();
  });

  if ("mediaSession" in navigator) {
    navigator.mediaSession.setActionHandler("play", () => audio.play());
    navigator.mediaSession.setActionHandler("pause", () => audio.pause());
    navigator.mediaSession.setActionHandler("nexttrack", () => player.next());
    navigator.mediaSession.setActionHandler("previoustrack", () => player.prev());
  }
}

async function shareSong(s) {
  const url = new URL(`index.html#/canciones?song=${encodeURIComponent(s.id)}`, location.href).toString();
  try {
    if (navigator.share) await navigator.share({ title: s.titulo, text: `Escucha “${s.titulo}” en BeefMusic`, url });
    else {
      await navigator.clipboard.writeText(url);
      toast("Enlace copiado");
    }
  } catch {
    /* el usuario canceló */
  }
}
