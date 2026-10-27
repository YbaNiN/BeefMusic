// Piezas HTML reutilizables para canciones (filas, tarjetas, etiquetas).
import { esc, icon, fmtDuration } from "./dom.js";

const GENRE_VARS = [
  [/trap/i, "--g-trap"],
  [/drill/i, "--g-drill"],
  [/dembow/i, "--g-dembow"],
  [/regg?a?et[oó]n|perreo/i, "--g-reggaeton"],
  [/boom ?bap|rap/i, "--g-boombap"],
  [/salsa|cumbia|bachata|latin/i, "--g-salsa"],
];

export function genreTag(estilo) {
  if (!estilo) return "";
  const match = GENRE_VARS.find(([re]) => re.test(estilo));
  return `<span class="genre" style="--c:var(${match ? match[1] : "--text-2"})">${esc(estilo)}</span>`;
}

export const cover = (s, cls = "") => window.BeefCover.html(s, cls);

const playGlyph = `<span class="play" aria-hidden="true">${icon("play", "icon--fill i-play")}${icon("pause", "icon--fill i-pause")}</span>`;

export function songCard(s) {
  const playable = Boolean(s.url);
  return `
    <article class="card" data-song="${esc(s.id)}" ${playable ? `data-play="${esc(s.id)}" role="button" tabindex="0" aria-label="Reproducir ${esc(s.titulo)}"` : ""}>
      <div class="card__art">${cover(s)}${playable ? playGlyph : ""}</div>
      <div>
        <div class="card__title clamp-1">${esc(s.titulo)}</div>
        <div class="card__meta clamp-1">@${esc(s.autor)}${s.estilo ? " · " + esc(s.estilo) : ""}</div>
      </div>
    </article>`;
}

export function songRow(s, n, { showVote = true } = {}) {
  const playable = Boolean(s.url);
  const dur = fmtDuration(s.duracion);
  return `
    <div class="row${playable ? "" : " row--noaudio"}" data-song="${esc(s.id)}" ${playable ? `data-play="${esc(s.id)}" role="button" tabindex="0" aria-label="Reproducir ${esc(s.titulo)}"` : ""}>
      <div class="row__n"><span>${n}</span><span class="eq" aria-hidden="true"><i></i><i></i><i></i></span></div>
      ${cover(s)}
      <div class="row__body">
        <div class="row__title clamp-1">${esc(s.titulo)}</div>
        <div class="row__meta">${genreTag(s.estilo)}<span class="clamp-1">${playable ? "@" + esc(s.autor) : "Audio pendiente · @" + esc(s.autor)}</span></div>
      </div>
      <span class="row__dur">${esc(dur)}</span>
      <div class="row__end">
        ${showVote ? likeButton(s) : ""}
        <button class="icon-btn" data-song-open="${esc(s.id)}" aria-label="Detalles y comentarios de ${esc(s.titulo)}">${icon("more", "icon--sm")}</button>
      </div>
    </div>`;
}

export function likeButton(s, { compact = true } = {}) {
  const on = s.userVote === "like";
  return `<button class="vote${compact ? " vote--compact" : ""}" data-vote="like" data-id="${esc(s.id)}" aria-pressed="${on}" aria-label="Me gusta, ${s.likes}">${icon("up", "icon--sm")}<span class="tabular">${s.likes}</span></button>`;
}

export function dislikeButton(s) {
  const on = s.userVote === "dislike";
  return `<button class="vote" data-vote="dislike" data-id="${esc(s.id)}" aria-pressed="${on}" aria-label="No me gusta, ${s.dislikes}">${icon("down", "icon--sm")}<span class="tabular">${s.dislikes}</span></button>`;
}

export const rowSkeleton = (n = 6) =>
  Array.from({ length: n }, () => `
    <div class="row" aria-hidden="true">
      <div class="row__n"></div><div class="skel" style="width:48px;aspect-ratio:1"></div>
      <div style="display:grid;gap:6px"><div class="skel" style="height:12px;width:60%"></div><div class="skel" style="height:10px;width:35%"></div></div>
    </div>`).join("");

export const cardSkeleton = (n = 6) =>
  Array.from({ length: n }, () => `
    <div class="card" aria-hidden="true"><div class="skel" style="aspect-ratio:1"></div>
    <div style="display:grid;gap:6px"><div class="skel" style="height:12px;width:80%"></div><div class="skel" style="height:10px;width:50%"></div></div></div>`).join("");

export function emptyState(iconName, title, text, action = "") {
  return `<div class="empty">${icon(iconName)}<div class="t-ui" style="color:var(--text)">${esc(title)}</div><div class="t-meta">${esc(text)}</div>${action}</div>`;
}
