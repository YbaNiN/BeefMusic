// Arranque de la app de una sola página.
import { auth } from "./api.js";
import { $, esc, icon } from "./dom.js";
import { store, loadSongs, getSong, sortSongs } from "./store.js";
import { player, initPlayerControls } from "./player.js";
import { initSheets, openSheet } from "./sheets.js";
import { defineRoute, startRouter, parseHash } from "./router.js";
import { initSongSheet, openSongSheet } from "./song-sheet.js";
import { initPedir, openPedir } from "./features/pedir.js";
import { initFeedback, openFeedback } from "./features/feedback.js";
import { initNotifications, openNotifications } from "./features/notifications.js";
import { homeView } from "./views/home.js";
import { songsView } from "./views/songs.js";
import { communityView } from "./views/community.js";
import { profileView } from "./views/profile.js";
import { userView } from "./views/user.js";
import { requestsView } from "./views/requests.js";
import { termsView, privacyView } from "./views/legal.js";
import { contactView } from "./views/contact.js";
import { initProfileEdit, openProfileEdit } from "./features/profile-edit.js";
import { getMe, onMeChange } from "./me.js";
import { avatarHtml } from "./user-ui.js";
import { vote } from "./store.js";

// Como antes: la portada exige sesión; Canciones se puede ver sin entrar.
const route = parseHash().name;
if (!auth.isLogged() && (route === "inicio" || route === "")) {
  location.replace("user-login.html");
} else {
  boot();
}

function boot() {
  paintUserArea();
  initSheets();
  initPlayerControls();
  initSongSheet();
  initPedir();
  initFeedback();
  initNotifications();
  initProfileEdit();

  defineRoute("inicio", homeView);
  defineRoute("canciones", songsView);
  defineRoute("comunidad", communityView);
  defineRoute("perfil", profileView);
  defineRoute("u", userView);
  defineRoute("peticiones", requestsView);
  defineRoute("terminos", termsView);
  defineRoute("privacidad", privacyView);
  defineRoute("contacto", contactView);
  startRouter();

  // Foto de perfil en la barra superior, si la persona tiene una.
  const paintAvatar = (me) => {
    const link = $("#appbar-avatar");
    if (link && me?.profile?.avatarUrl) link.innerHTML = avatarHtml(auth.user(), me.profile.avatarUrl, "avatar--sm");
  };
  getMe().then(paintAvatar).catch(() => {});
  onMeChange(paintAvatar);

  // Recuperar la última canción (en pausa) cuando lleguen las canciones.
  loadSongs()
    .then((songs) => player.restore(songs))
    .catch(() => {});

  document.addEventListener("click", onClick);
  document.addEventListener("keydown", onKey);
  $("#mini").addEventListener("click", (e) => {
    if (!e.target.closest("button")) openSheet("sheet-np");
  });
  $("#mini").addEventListener("keydown", (e) => {
    if ((e.key === "Enter" || e.key === " ") && e.target.id === "mini") {
      e.preventDefault();
      openSheet("sheet-np");
    }
  });
}

function paintUserArea() {
  const el = $("#appbar-user");
  if (!auth.isLogged()) {
    el.innerHTML = `<a class="btn btn--sm" href="user-login.html">${icon("login", "icon--sm")}Entrar</a>`;
    return;
  }
  const user = auth.user();
  el.innerHTML = `
    <button class="icon-btn" data-action="notifs" aria-label="Notificaciones">${icon("bell")}<span class="badge-dot" data-notif-badge hidden>0</span></button>
    <a class="appbar__avatar" id="appbar-avatar" href="#/perfil" aria-label="Tu perfil sonoro">${avatarHtml(user, "", "avatar--sm")}</a>`;
}

// La cola es la lista visible donde se pulsó (novedades, top, canciones…).
function queueFor(el) {
  const box = el.closest("[data-queue]");
  if (!box) return sortSongs(store.songs, "recientes");
  return [...box.querySelectorAll("[data-play]")].map((x) => getSong(x.dataset.play)).filter(Boolean);
}

function onClick(e) {
  const t = e.target;

  // Al ir a entrar o registrarse, recordar dónde estaba para volver después.
  const authLink = t.closest('a[href^="user-login.html"], a[href^="registro-usuario.html"]');
  if (authLink) {
    const base = authLink.getAttribute("href").split("?")[0];
    const here = location.hash && location.hash !== "#/" ? location.hash : "";
    authLink.setAttribute("href", here ? `${base}?next=${encodeURIComponent(here)}` : base);
    return;
  }

  const voteBtn = t.closest("[data-vote]");
  if (voteBtn) {
    e.stopPropagation();
    voteBtn.classList.remove("pop");
    void voteBtn.offsetWidth;
    voteBtn.classList.add("pop");
    vote(voteBtn.dataset.id, voteBtn.dataset.vote);
    return;
  }

  const open = t.closest("[data-song-open]");
  if (open) {
    e.stopPropagation();
    openSongSheet(open.dataset.songOpen);
    return;
  }

  const action = t.closest("[data-action]");
  if (action) {
    const a = action.dataset.action;
    if (a === "pedir") return openPedir("form");
    if (a === "asistente") return openPedir("ia");
    if (a === "sugerencia" || a === "reporte") return openFeedback(a);
    if (a === "notifs") return openNotifications();
    if (a === "edit-profile") return openProfileEdit();
    if (a === "logout") return auth.logout();
    if (a === "reload-songs") return loadSongs({ force: true }).catch(() => {});
    if (a === "song-current") {
      const s = player.currentSong();
      if (s) {
        document.getElementById("sheet-np").close();
        openSongSheet(s.id);
      }
      return;
    }
  }

  const play = t.closest("[data-play]");
  if (play && !t.closest("a")) {
    player.playFrom(queueFor(play), play.dataset.play);
  }
}

function onKey(e) {
  if (e.key !== "Enter" && e.key !== " ") return;
  const play = e.target.closest && e.target.closest('[data-play][role="button"]');
  if (play && e.target === play) {
    e.preventDefault();
    play.click();
  }
}
