// Estado compartido de canciones. Todas las vistas leen de aquí, así un voto
// hecho en el reproductor se ve al momento en la lista y en la ficha.
import { songsApi, auth } from "./api.js";
import { toast } from "./dom.js";

const listeners = new Set();

export const store = {
  songs: [],
  loaded: false,
  error: null,
};

let pending = null;

export function onSongsChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emit(changedId = null) {
  listeners.forEach((fn) => fn(store.songs, changedId));
}

export function handle(name) {
  return String(name || "anónimo").replace(/^@/, "");
}

function normalize(s) {
  return {
    id: s.id,
    titulo: s.titulo || s.title || "Tema sin título",
    estilo: (s.estilo || s.style || "").trim(),
    duracion: s.duracion ?? s.duration ?? null,
    descripcion: (s.descripcion || s.descripcion_peticion || s.description || "").trim(),
    autor: handle(s.autor || s.requester || s.nick),
    estado: s.estado || "publicada",
    url: s.url_audio || s.audio_url || "",
    created_at: s.created_at || null,
    likes: Number(s.likes ?? 0),
    dislikes: Number(s.dislikes ?? 0),
    userVote: s.userVote || s.votoUsuario || null,
  };
}

export function loadSongs({ force = false } = {}) {
  if (pending && !force) return pending;
  if (store.loaded && !force) return Promise.resolve(store.songs);
  pending = songsApi
    .list()
    .then((list) => {
      if (!Array.isArray(list)) throw new Error("La API de canciones no devolvió una lista");
      store.songs = list.map(normalize);
      store.loaded = true;
      store.error = null;
      emit();
      return store.songs;
    })
    .catch((err) => {
      store.error = err;
      pending = null;
      emit();
      throw err;
    });
  return pending;
}

export const getSong = (id) => store.songs.find((s) => String(s.id) === String(id)) || null;

export function sortSongs(list, mode = "recientes") {
  const byDate = (a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0);
  const copy = [...list];
  if (mode === "top") return copy.sort((a, b) => b.likes - a.likes || byDate(a, b));
  return copy.sort(byDate);
}

const capitalize = (s) => s.charAt(0).toUpperCase() + s.slice(1);

// Estilos más frecuentes, para los filtros ("rap" y "Rap" cuentan como uno).
export function topStyles(limit = 6) {
  const count = new Map();
  store.songs.forEach((s) => {
    if (!s.estilo) return;
    const key = s.estilo.toLowerCase();
    const prev = count.get(key);
    count.set(key, { label: prev?.label || capitalize(s.estilo), n: (prev?.n || 0) + 1 });
  });
  return [...count.values()].sort((a, b) => b.n - a.n).slice(0, limit).map((x) => x.label);
}

const voting = new Set();

export async function vote(id, tipo) {
  if (!auth.isLogged()) {
    toast("Inicia sesión para votar", { error: true });
    return null;
  }
  if (voting.has(id)) return null;
  voting.add(id);
  try {
    const r = await songsApi.vote(id, tipo);
    const s = getSong(id);
    if (s) {
      if (typeof r.likes === "number") s.likes = r.likes;
      if (typeof r.dislikes === "number") s.dislikes = r.dislikes;
      s.userVote = r.userVote ?? null;
      emit(id);
    }
    return r;
  } catch (err) {
    toast(err.message || "No se pudo registrar el voto", { error: true });
    return null;
  } finally {
    voting.delete(id);
  }
}
