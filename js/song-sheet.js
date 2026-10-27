// Ficha de canción: datos, reproducir, votos e hilo de comentarios.
import { auth, songsApi } from "./api.js";
import { $, esc, icon, fmtDuration, timeAgo, toast, setStatus, withBusy } from "./dom.js";
import { getSong, onSongsChange } from "./store.js";
import { cover, genreTag, likeButton, dislikeButton } from "./song-ui.js";
import { syncSongEls } from "./player.js";
import { openSheet } from "./sheets.js";
import { parseHash, replaceParams } from "./router.js";

const sheet = () => document.getElementById("sheet-song");
let currentId = null;

const ESTADOS = { publicada: "status--terminada", terminada: "status--terminada", en_produccion: "status--produccion", pendiente: "status--pendiente" };

export function openSongSheet(id) {
  const s = getSong(id);
  if (!s) {
    toast("No se encontró esa canción", { error: true });
    return;
  }
  currentId = String(s.id);
  const body = $("#song-sheet-body");
  const dur = fmtDuration(s.duracion);
  const date = s.created_at ? timeAgo(s.created_at) : "";
  const estadoCls = ESTADOS[String(s.estado).toLowerCase()] || "";

  body.innerHTML = `
    <div class="song-hero" data-song="${esc(s.id)}">
      ${cover(s, "song-hero__cover")}
      <div class="song-hero__info">
        <div class="song-hero__tags">${genreTag(s.estilo)}<span class="status ${estadoCls}">${esc(s.estado)}</span></div>
        <h2 class="t-h1" id="song-title">${esc(s.titulo)}</h2>
        <p class="t-meta">@${esc(s.autor)}${dur ? " · " + esc(dur) : ""}${date ? " · " + esc(date) : ""}</p>
        <div class="song-hero__actions" id="song-actions">${actionsHtml(s)}</div>
      </div>
    </div>
    ${s.descripcion ? `<section><div class="t-kicker">La historia</div><p class="song-desc">${esc(s.descripcion)}</p></section>` : ""}
    <section aria-labelledby="comments-title">
      <div class="section__head" style="margin-bottom:var(--s-2)">
        <h3 class="t-h3" id="comments-title">Comentarios <span class="t-meta tabular" id="comments-count"></span></h3>
        <button class="icon-btn" id="comments-reload" aria-label="Recargar comentarios">${icon("comment", "icon--sm")}</button>
      </div>
      ${auth.isLogged()
        ? `<form class="composer" id="comment-form">
             <label class="sr-only" for="comment-input">Escribe un comentario</label>
             <textarea class="textarea" id="comment-input" maxlength="800" rows="2" placeholder="Añade un comentario…"></textarea>
             <button class="btn btn--primary btn--sm" type="submit">${icon("send", "icon--sm")}Comentar</button>
           </form>`
        : `<a class="btn btn--outline btn--block" href="user-login.html">${icon("login", "icon--sm")}Entra para comentar</a>`}
      <p class="form-status" id="comment-status" role="status" aria-live="polite"></p>
      <div id="comments-root" class="comments"></div>
    </section>
  `;

  syncSongEls(body);
  openSheet("sheet-song");
  if (parseHash().name === "canciones") replaceParams({ song: s.id });
  loadComments();

  const form = $("#comment-form");
  if (form) form.addEventListener("submit", onSubmitComment);
  $("#comments-reload").addEventListener("click", loadComments);
}

function actionsHtml(s) {
  return `
    ${s.url
      ? `<button class="play" data-play="${esc(s.id)}" aria-label="Reproducir ${esc(s.titulo)}">${icon("play", "icon--fill i-play")}${icon("pause", "icon--fill i-pause")}</button>`
      : `<span class="t-meta">El audio de este tema todavía no está disponible.</span>`}
    <div class="votes">${likeButton(s, { compact: false })}${dislikeButton(s)}</div>`;
}

/* ---------------- Comentarios ---------------- */
function commentNode(node) {
  const name = node.user?.username || node.username || "unknown";
  const replies = (node.replies || []).map(commentNode).join("");
  return `
    <div class="comment" data-comment-id="${esc(node.id)}">
      <span class="avatar avatar--sm" aria-hidden="true">${esc(name.charAt(0).toUpperCase())}</span>
      <div style="min-width:0">
        <div class="comment__head"><span class="comment__name">@${esc(name)}</span><span class="t-caption">${esc(timeAgo(node.createdAt || node.created_at))}</span></div>
        <p class="comment__body">${esc(node.body)}</p>
        <div class="comment__actions">
          <button class="btn btn--ghost btn--sm" data-c="reply">Responder</button>
          <button class="btn btn--ghost btn--sm" data-c="report">Reportar</button>
        </div>
        <form class="inline-box" data-box="reply" hidden>
          <textarea class="textarea" rows="2" maxlength="800" placeholder="Tu respuesta…" aria-label="Respuesta a @${esc(name)}"></textarea>
          <div class="inline-box__actions"><button class="btn btn--primary btn--sm" type="submit">Responder</button><button class="btn btn--ghost btn--sm" type="button" data-c="cancel">Cancelar</button></div>
        </form>
        <form class="inline-box" data-box="report" hidden>
          <input class="input" maxlength="500" placeholder="Motivo del reporte" aria-label="Motivo del reporte" />
          <div class="inline-box__actions"><button class="btn btn--sm" type="submit">${icon("flag", "icon--sm")}Enviar reporte</button><button class="btn btn--ghost btn--sm" type="button" data-c="cancel">Cancelar</button></div>
        </form>
        ${replies ? `<div class="comment__replies">${replies}</div>` : ""}
      </div>
    </div>`;
}

function countAll(nodes) {
  return nodes.reduce((n, c) => n + 1 + countAll(c.replies || []), 0);
}

async function loadComments() {
  const id = currentId;
  const root = $("#comments-root");
  if (!root || !id) return;
  root.innerHTML = `<div class="comments-skel">${'<div class="skel" style="height:14px;width:70%"></div>'.repeat(3)}</div>`;
  try {
    const data = await songsApi.commentsTree(id);
    if (id !== currentId) return;
    const items = data.items || [];
    $("#comments-count").textContent = items.length ? `· ${countAll(items)}` : "";
    root.innerHTML = items.length
      ? items.map(commentNode).join("")
      : `<p class="t-meta comments-empty">Aún no hay comentarios. Sé el primero.</p>`;
  } catch (err) {
    root.innerHTML = `<p class="t-meta comments-empty">${icon("alert", "icon--sm")} ${esc(err.message)}</p>`;
  }
}

async function onSubmitComment(e) {
  e.preventDefault();
  const input = $("#comment-input");
  const text = input.value.trim();
  if (!text) return input.focus();
  const btn = e.submitter || e.target.querySelector("button[type=submit]");
  await withBusy(btn, "Enviando", async () => {
    try {
      await songsApi.comment(currentId, text, null);
      input.value = "";
      setStatus($("#comment-status"), "");
      await loadComments();
    } catch (err) {
      setStatus($("#comment-status"), err.message, "error");
    }
  });
}

function initCommentActions() {
  const body = $("#song-sheet-body");

  body.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-c]");
    if (!btn) return;
    const item = btn.closest(".comment");
    const toggleBox = (name) => {
      item.querySelectorAll(":scope > div > .inline-box").forEach((b) => (b.hidden = b.dataset.box !== name || !b.hidden));
      const box = item.querySelector(`:scope > div > [data-box="${name}"]`);
      if (box && !box.hidden) box.querySelector("textarea, input").focus();
    };
    if (btn.dataset.c === "cancel") {
      btn.closest(".inline-box").hidden = true;
      return;
    }
    if (!auth.isLogged()) {
      toast(btn.dataset.c === "reply" ? "Inicia sesión para responder" : "Inicia sesión para reportar", { error: true });
      return;
    }
    toggleBox(btn.dataset.c);
  });

  body.addEventListener("submit", async (e) => {
    const box = e.target.closest(".inline-box");
    if (!box) return;
    e.preventDefault();
    const commentId = box.closest(".comment").dataset.commentId;
    const field = box.querySelector("textarea, input");
    const text = field.value.trim();
    if (!text) return field.focus();
    const btn = box.querySelector("button[type=submit]");
    await withBusy(btn, "Enviando", async () => {
      try {
        if (box.dataset.box === "reply") {
          await songsApi.comment(currentId, text, commentId);
          await loadComments();
        } else {
          await songsApi.reportComment(commentId, text);
          box.hidden = true;
          field.value = "";
          toast("Reporte enviado");
        }
      } catch (err) {
        toast(err.message, { error: true });
      }
    });
  });
}

export function initSongSheet() {
  initCommentActions();
  sheet().addEventListener("close", () => {
    // El evento llega en diferido: si ya se ha abierto otra canción, no tocar nada.
    if (sheet().open) return;
    currentId = null;
    if (parseHash().name === "canciones") replaceParams({});
  });
  // Mantener votos al día si cambian desde otro sitio (p. ej. el reproductor).
  onSongsChange((_, changedId) => {
    if (!currentId || (changedId != null && String(changedId) !== currentId)) return;
    const s = getSong(currentId);
    const el = $("#song-actions");
    if (s && el) {
      el.innerHTML = actionsHtml(s);
      syncSongEls($("#song-sheet-body"));
    }
  });
}
