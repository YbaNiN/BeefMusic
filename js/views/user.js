// Perfil público (#/u/usuario): bio, enlaces, seguidores, seguir y últimos likes.
import { auth, usersApi } from "../api.js";
import { esc, icon, toast } from "../dom.js";
import { getSong, loadSongs } from "../store.js";
import { songRow, emptyState } from "../song-ui.js";
import { syncSongEls } from "../player.js";
import { onMeChange } from "../me.js";
import { avatarHtml, socialLinks, levelFromXp, titleForLevel } from "../user-ui.js";

const usernameFrom = (params) => {
  const raw = (params.path || "").replace(/^@/, "");
  return raw === "me" ? auth.user() : raw;
};

function followButton(isFollowing) {
  return isFollowing
    ? `<button class="btn btn--outline" id="follow-btn" aria-pressed="true">${icon("user-check", "icon--sm")}Siguiendo</button>`
    : `<button class="btn btn--primary" id="follow-btn" aria-pressed="false">${icon("user-plus", "icon--sm")}Seguir</button>`;
}

function render(root, data) {
  const username = data.user?.username || "usuario";
  const profile = data.profile || {};
  const social = data.social || {};
  const sound = data.sound || {};
  const lvl = data.level || {};
  const isOwner = auth.isLogged() && auth.user().toLowerCase() === username.toLowerCase();
  const level = lvl.level || levelFromXp(lvl.xp).level;
  const title = lvl.title || titleForLevel(level);
  const progress = Math.max(0, Math.min(100, Number(lvl.progressPercent) || 0));
  const links = socialLinks(profile.links);

  // Últimos likes: usamos las canciones del store para poder reproducirlas.
  const liked = (data.topLikedSongs || []).map((s) => getSong(s.id)).filter(Boolean);

  root.innerHTML = `
    <header class="user-hero">
      ${avatarHtml(username, profile.avatarUrl, "avatar--xl")}
      <div class="user-hero__info">
        <p class="t-kicker">Nivel ${esc(level)} · ${esc(title)}</p>
        <h1 class="t-h1 clamp-1">@${esc(username)}</h1>
        <p class="user-hero__bio">${profile.bio ? esc(profile.bio) : `<span class="t-meta">${isOwner ? "Aún no has escrito tu bio." : "Sin bio."}</span>`}</p>
        <p class="t-meta tabular" id="follow-counts">
          <strong class="text-strong" id="followers-n">${social.followersCount ?? 0}</strong> seguidores ·
          <strong class="text-strong">${social.followingCount ?? 0}</strong> siguiendo
        </p>
        <div class="user-hero__actions">
          ${isOwner
            ? `<button class="btn btn--outline" data-action="edit-profile">${icon("pencil", "icon--sm")}Editar perfil</button>
               ${profile.isPublic === false ? `<span class="status status--plain">${icon("lock", "icon--sm")}Perfil privado</span>` : ""}`
            : auth.isLogged() && data.user?.id != null
              ? followButton(Boolean(social.isFollowing))
              : `<a class="btn btn--outline" href="user-login.html">${icon("login", "icon--sm")}Entra para seguir</a>`}
          ${links}
        </div>
      </div>
    </header>

    <section class="section">
      <div class="xp-line"><span class="t-meta">Progreso al nivel ${esc(Number(level) + 1)}</span><span class="t-meta tabular">${progress}%</span></div>
      <div class="xp" role="progressbar" aria-valuenow="${progress}" aria-valuemin="0" aria-valuemax="100" aria-label="Progreso de nivel"><span style="--v:${progress}%"></span></div>
      <div class="stats" style="margin-top:var(--s-4)">
        <div class="stat"><div class="stat__label">Votos</div><div class="stat__value">${esc(sound.totalVotes ?? 0)}</div></div>
        <div class="stat"><div class="stat__label">Likes</div><div class="stat__value">${esc(sound.totalLikes ?? 0)}</div></div>
        <div class="stat"><div class="stat__label">Toxicidad</div><div class="stat__value">${esc(sound.toxicity ?? 0)}%</div></div>
        <div class="stat"><div class="stat__label">Estilo top</div><div class="stat__value stat__value--text clamp-1">${esc(sound.dominantGenre || "—")}</div></div>
      </div>
      ${(sound.badges || []).length ? `<div class="tags" style="margin-top:var(--s-3)">${sound.badges.map((b) => `<span class="tag">${icon("trophy", "icon--sm")}${esc(b.label || "")}</span>`).join("")}</div>` : ""}
    </section>

    <section class="section" aria-labelledby="liked-title">
      <div class="section__head"><h2 class="t-h2" id="liked-title">Últimos likes</h2></div>
      <div class="list" data-queue>
        ${liked.length ? liked.map((s, i) => songRow(s, i + 1)).join("") : emptyState("up", "Todavía sin likes", isOwner ? "Dale like a tus temas favoritos y saldrán aquí." : "Cuando le dé like a algún tema, saldrá aquí.")}
      </div>
    </section>
  `;
  syncSongEls(root);
  bindFollow(root, data);
}

function bindFollow(root, data) {
  const btn = root.querySelector("#follow-btn");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    const wasFollowing = btn.getAttribute("aria-pressed") === "true";
    const countEl = root.querySelector("#followers-n");
    const prevCount = Number(countEl.textContent) || 0;
    // Optimista: cambia ya y revierte si falla.
    btn.outerHTML = followButton(!wasFollowing);
    countEl.textContent = String(Math.max(0, prevCount + (wasFollowing ? -1 : 1)));
    const next = root.querySelector("#follow-btn");
    next.disabled = true;
    try {
      if (wasFollowing) await usersApi.unfollow(data.user.id);
      else await usersApi.follow(data.user.id);
      data.social = { ...data.social, isFollowing: !wasFollowing, followersCount: Number(countEl.textContent) };
      toast(wasFollowing ? `Has dejado de seguir a @${data.user.username}` : `Ahora sigues a @${data.user.username}`);
    } catch (err) {
      next.outerHTML = followButton(wasFollowing);
      countEl.textContent = String(prevCount);
      toast(err.message || "No se pudo completar", { error: true });
    } finally {
      bindFollow(root, data);
      const b = root.querySelector("#follow-btn");
      if (b) b.disabled = false;
    }
  });
}

async function load(root, username) {
  root.innerHTML = `
    <header class="user-hero" aria-busy="true">
      <div class="skel" style="width:112px;height:112px;border-radius:50%"></div>
      <div class="user-hero__info"><div class="skel" style="height:12px;width:120px"></div><div class="skel" style="height:32px;width:220px"></div><div class="skel" style="height:12px;width:60%"></div></div>
    </header>`;
  if (!username) {
    root.innerHTML = emptyState("user", "Falta el usuario", "Busca a alguien desde Comunidad.", `<a class="btn btn--sm" href="#/comunidad">Ir a Comunidad</a>`);
    return;
  }
  try {
    const [data] = await Promise.all([usersApi.get(username), loadSongs().catch(() => null)]);
    if (root.isConnected) render(root, data);
  } catch (err) {
    const back = `<a class="btn btn--sm" href="#/comunidad">Volver a Comunidad</a>`;
    if (err.status === 404) root.innerHTML = emptyState("user", `No existe @${username}`, "Revisa que el nombre de usuario esté bien escrito.", back);
    else if (err.status === 403) root.innerHTML = emptyState("lock", "Este perfil es privado", `@${username} ha decidido no mostrar su perfil.`, back);
    else root.innerHTML = emptyState("alert", "No se pudo cargar el perfil", err.message, back);
  }
}

export const userView = {
  nav: "comunidad",
  title: (params) => "@" + (usernameFrom(params) || "perfil"),
  mount(root, params) {
    const username = usernameFrom(params);
    load(root, username);
    // Si edito mi perfil estando en él, se repinta.
    return onMeChange(() => {
      if (auth.user().toLowerCase() === String(username).toLowerCase()) load(root, username);
    });
  },
};
