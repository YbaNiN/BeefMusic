// Vista Comunidad: buscar perfiles y feed de actividad de la gente que sigues.
import { auth, usersApi } from "../api.js";
import { esc, icon, timeAgo } from "../dom.js";
import { getMe } from "../me.js";
import { getSong, loadSongs } from "../store.js";
import { cover } from "../song-ui.js";
import { avatarHtml } from "../user-ui.js";
import { navigate } from "../router.js";

const PAGE = 20;

function feedItem(ev, myId) {
  const actor = ev.actor?.username || "alguien";
  const who = `<a class="link-strong" href="#/u/${encodeURIComponent(actor)}">@${esc(actor)}</a>`;
  const meta = ev.metadata || {};
  let text = `${who} tuvo actividad en BeefMusic`;
  let side = "";

  if (ev.verb === "comment_song") {
    const song = getSong(ev.objectId);
    const title = meta.songTitle || song?.titulo || "una canción";
    text = `${who} comentó en <button class="link-strong" data-song-open="${esc(ev.objectId)}">${esc(title)}</button>`;
    if (song) side = `<button class="feed-item__cover" data-song-open="${esc(song.id)}" aria-label="Abrir ${esc(song.titulo)}">${cover(song)}</button>`;
  } else if (ev.verb === "follow") {
    const toMe = myId != null && String(ev.objectId) === String(myId);
    text = `${who} ${toMe ? "empezó a seguirte" : "empezó a seguir a alguien"}`;
    side = `<span class="feed-item__icon">${icon("users", "icon--sm")}</span>`;
  }

  return `
    <article class="feed-item">
      <a href="#/u/${encodeURIComponent(actor)}" aria-label="Perfil de @${esc(actor)}">${avatarHtml(actor, "", "avatar--sm")}</a>
      <div class="feed-item__body">
        <p class="t-ui">${text}</p>
        <span class="t-caption">${esc(timeAgo(ev.createdAt))}</span>
      </div>
      ${side}
    </article>`;
}

export const communityView = {
  title: "Comunidad",
  async mount(root) {
    const logged = auth.isLogged();
    root.innerHTML = `
      <header class="view-head">
        <p class="t-kicker">Gente BeefMusic</p>
        <h1 class="t-h1">Comunidad</h1>
      </header>

      <form class="search" id="user-search" role="search">
        ${icon("search", "icon--sm")}
        <label class="sr-only" for="user-search-input">Buscar un perfil por usuario</label>
        <input id="user-search-input" type="search" placeholder="Busca a alguien por su @usuario" autocomplete="off" autocapitalize="off" spellcheck="false" enterkeyhint="go" />
        <button class="icon-btn" type="submit" aria-label="Ver perfil">${icon("arrow-right", "icon--sm")}</button>
      </form>
      <p class="t-caption" style="margin-top:6px">Escribe el nombre exacto de usuario (sin @).</p>

      ${logged
        ? `<div class="cta-row">
             <a class="btn btn--sm" href="#/u/${encodeURIComponent(auth.user())}">${icon("user", "icon--sm")}Mi perfil público</a>
             <button class="btn btn--sm btn--outline" data-action="edit-profile">${icon("pencil", "icon--sm")}Editar perfil</button>
           </div>
           <section class="section" aria-labelledby="feed-title">
             <div class="section__head"><h2 class="t-h2" id="feed-title">Actividad</h2></div>
             <p class="t-meta" style="margin:-6px 0 var(--s-3)">Lo que comentan y a quién siguen las personas que sigues.</p>
             <div class="feed" id="feed"></div>
             <button class="btn btn--outline btn--block" id="feed-more" hidden>Cargar más</button>
           </section>`
        : `<section class="panel panel--raised soon" style="margin-top:var(--s-6)">
             ${icon("users")}
             <h2 class="t-h3">Entra para ver tu feed</h2>
             <p class="t-meta">Sigue a gente, mira lo que comentan y edita tu perfil público.</p>
             <div class="cta-row" style="margin-top:0"><a class="btn btn--primary" href="user-login.html">${icon("login", "icon--sm")}Entrar</a><a class="btn btn--outline" href="registro-usuario.html">Crear cuenta</a></div>
           </section>`}
    `;

    root.querySelector("#user-search").addEventListener("submit", (e) => {
      e.preventDefault();
      const u = root.querySelector("#user-search-input").value.trim().replace(/^@/, "");
      if (u) navigate("u/" + encodeURIComponent(u));
    });

    if (!logged) return;

    const feed = root.querySelector("#feed");
    const more = root.querySelector("#feed-more");
    let offset = 0;
    let myId = null;
    let busy = false;

    feed.innerHTML = Array.from({ length: 4 }, () => `
      <div class="feed-item" aria-hidden="true"><div class="skel" style="width:32px;height:32px;border-radius:50%"></div>
      <div style="display:grid;gap:6px"><div class="skel" style="height:12px;width:70%"></div><div class="skel" style="height:10px;width:30%"></div></div></div>`).join("");

    async function loadMore() {
      if (busy) return;
      busy = true;
      more.disabled = true;
      try {
        const data = await usersApi.feed(offset, PAGE);
        const items = Array.isArray(data.items) ? data.items : [];
        if (offset === 0) feed.innerHTML = "";
        if (!items.length && offset === 0) {
          feed.innerHTML = `<div class="empty">${icon("users")}<div class="t-ui" style="color:var(--text)">Tu feed está vacío</div><div class="t-meta">Busca a alguien arriba y síguelo para ver aquí su actividad.</div></div>`;
        }
        feed.insertAdjacentHTML("beforeend", items.map((ev) => feedItem(ev, myId)).join(""));
        offset += items.length;
        more.hidden = data.nextOffset == null;
      } catch (err) {
        if (offset === 0) feed.innerHTML = `<div class="empty">${icon("alert")}<div class="t-ui" style="color:var(--text)">No se pudo cargar el feed</div><div class="t-meta">${esc(err.message)}</div></div>`;
        else more.hidden = false;
      } finally {
        busy = false;
        more.disabled = false;
      }
    }

    more.addEventListener("click", loadMore);

    // Las portadas del feed y "empezó a seguirte" necesitan canciones y mi id.
    const [me] = await Promise.all([getMe().catch(() => null), loadSongs().catch(() => null)]);
    myId = me?.user?.id ?? null;
    if (root.isConnected) loadMore();
  },
};
