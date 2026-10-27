// Vista Perfil: perfil sonoro (nivel, mood, géneros, 100 logros) + ajustes y ayuda.
import { auth, usersApi } from "../api.js";
import { esc, icon, debounce } from "../dom.js";
import { getMe, onMeChange } from "../me.js";
import { avatarHtml, levelFromXp, titleForLevel } from "../user-ui.js";
import { evaluate, SORTS } from "../achievements.js";

const GENRE_VARS = [
  [/trap/i, "--g-trap"], [/drill/i, "--g-drill"], [/dembow/i, "--g-dembow"],
  [/regg?a?et[oó]n|perreo/i, "--g-reggaeton"], [/boom ?bap|rap/i, "--g-boombap"], [/salsa|cumbia|latin/i, "--g-salsa"],
];
const genreVar = (name) => (GENRE_VARS.find(([re]) => re.test(name || "")) || [null, "--beef"])[1];
const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : 0);

// Filtros de logros: se conservan al volver a la vista.
const achv = { filter: "all", q: "", sort: "smart" };

const menuItem = ({ href, action, iconName, label, hint = "", external = false }) => {
  const inner = `<span class="menu__icon">${icon(iconName)}</span><span class="menu__text"><span class="menu__label">${label}</span>${hint ? `<span class="t-meta">${hint}</span>` : ""}</span>${icon(external ? "external" : "chevron-right", "icon--sm menu__chev")}`;
  return href ? `<a class="menu__item" href="${href}">${inner}</a>` : `<button class="menu__item" data-action="${action}">${inner}</button>`;
};

function settingsHtml(logged) {
  return `
    <section class="section">
      <h2 class="t-kicker menu__title">Ajustes y ayuda</h2>
      <nav class="menu">
        ${logged ? menuItem({ action: "edit-profile", iconName: "pencil", label: "Editar perfil", hint: "Bio, foto, enlaces y privacidad" }) : ""}
        ${menuItem({ href: "#/peticiones", iconName: "list", label: "Peticiones en curso", hint: "En qué punto está cada petición" })}
        ${menuItem({ action: "asistente", iconName: "sparkles", label: "Asistente de letras" })}
        ${menuItem({ action: "sugerencia", iconName: "bulb", label: "Enviar sugerencia" })}
        ${menuItem({ action: "reporte", iconName: "flag", label: "Reportar un problema" })}
        ${menuItem({ href: "#/contacto", iconName: "mail", label: "Contacto" })}
        ${menuItem({ href: "#/terminos", iconName: "file", label: "Términos de uso" })}
        ${menuItem({ href: "#/privacidad", iconName: "file", label: "Privacidad" })}
        ${logged ? menuItem({ action: "logout", iconName: "logout", label: "Cerrar sesión" }) : ""}
      </nav>
    </section>`;
}

function guestHtml() {
  return `
    <header class="view-head"><p class="t-kicker">Tu cuenta</p><h1 class="t-h1">Perfil sonoro</h1></header>
    <section class="panel panel--raised soon">
      ${icon("trophy")}
      <h2 class="t-h3">Tu identidad sonora te espera</h2>
      <p class="t-meta">Entra para ver tu nivel, tus géneros y desbloquear 100 logros votando canciones.</p>
      <div class="cta-row" style="margin-top:0"><a class="btn btn--primary" href="user-login.html">${icon("login", "icon--sm")}Entrar</a><a class="btn btn--outline" href="registro-usuario.html">Crear cuenta</a></div>
    </section>
    ${settingsHtml(false)}`;
}

function levelInfo(p) {
  const xp = num(p.xp);
  let level = num(p.level);
  let into = num(p.xpIntoLevel);
  let next = num(p.xpForNextLevel);
  if (!level || !next) {
    const calc = levelFromXp(xp);
    level = level || calc.level;
    into = calc.xpIntoLevel;
    next = calc.xpForNextLevel;
  }
  const pct = next > 0 ? Math.max(0, Math.min(100, Math.round((into / next) * 100))) : 100;
  return { xp, level, into, next, pct, title: (p.title || "").trim() || titleForLevel(level), max: Boolean(p.isMaxLevel) };
}

function genresHtml(genres) {
  if (!genres.length) return `<div class="empty">${icon("music")}<div class="t-ui" style="color:var(--text)">Sin datos todavía</div><div class="t-meta">Vota algunas canciones y vuelve para ver tus géneros.</div><a class="btn btn--sm" href="#/canciones">Ir a canciones</a></div>`;
  return `<div class="genre-bars">${[...genres]
    .sort((a, b) => num(b.percent) - num(a.percent))
    .map((g) => `
      <div class="genre-bar" style="--c:var(${genreVar(g.name)})">
        <div class="genre-bar__top"><span class="t-ui genre-bar__name">${esc(g.name || "—")}</span><span class="t-meta tabular">${num(g.percent)}%</span></div>
        <div class="genre-bar__track"><span style="width:${Math.min(100, num(g.percent))}%"></span></div>
        <div class="genre-bar__votes t-caption tabular">${icon("up", "icon--sm")}${num(g.likes)} ${icon("down", "icon--sm")}${num(g.dislikes)}</div>
      </div>`).join("")}</div>`;
}

function achievementsHtml(items) {
  if (!items.length) return `<div class="empty">${icon("search")}<div class="t-ui" style="color:var(--text)">Sin resultados</div><div class="t-meta">No hay logros con ese filtro o búsqueda.</div></div>`;
  return items.map((a) => `
    <article class="achv${a.unlocked ? "" : " achv--locked"}">
      <div class="achv__icon">${icon(a.unlocked ? a.icon : "lock")}</div>
      <div style="min-width:0">
        <div class="achv__title">${esc(a.title)}</div>
        <div class="achv__desc">${esc(a.desc)}</div>
        ${a.unlocked
          ? `<div class="achv__done t-caption">${icon("check", "icon--sm")}Conseguido</div>`
          : `<div class="xp" aria-hidden="true"><span style="--v:${Math.round(a.ratio * 100)}%"></span></div><div class="t-caption tabular" style="margin-top:4px">${Math.min(a.current, a.target)}/${a.target}</div>`}
      </div>
    </article>`).join("");
}

function render(root, p, me) {
  const user = p.username || auth.user();
  const lvl = levelInfo(p);
  const all = evaluate(p);
  const unlockedN = all.filter((a) => a.unlocked).length;
  const avatarUrl = me?.profile?.avatarUrl || "";

  root.innerHTML = `
    <header class="level-hero">
      <div class="level-hero__top">
        ${avatarHtml(user, avatarUrl, "avatar--lg")}
        <div style="min-width:0">
          <p class="t-kicker">Perfil sonoro</p>
          <h1 class="t-h1 clamp-1">@${esc(user)}</h1>
          <p class="t-meta"><span class="text-beef">${esc(lvl.title)}</span> · ${esc(lvl.xp)} XP en total</p>
        </div>
      </div>
      <div class="level-hero__level">
        <div class="level-badge" aria-label="Nivel ${lvl.level}"><span class="t-caption">Nivel</span><strong>${lvl.level}</strong></div>
        <div style="flex:1;min-width:0">
          <div class="xp-line"><span class="t-meta tabular">${lvl.into}/${lvl.next} XP</span><span class="t-meta">${lvl.max ? "Nivel máximo" : `+${Math.max(0, lvl.next - lvl.into)} XP para el ${lvl.level + 1}`}</span></div>
          <div class="xp" role="progressbar" aria-valuenow="${lvl.pct}" aria-valuemin="0" aria-valuemax="100" aria-label="Progreso de nivel"><span style="--v:${lvl.pct}%"></span></div>
        </div>
      </div>
      <div class="cta-row" style="margin-top:0">
        <a class="btn btn--sm" href="#/u/${encodeURIComponent(user)}">${icon("user", "icon--sm")}Ver mi perfil público</a>
        <button class="btn btn--sm btn--outline" data-action="edit-profile">${icon("pencil", "icon--sm")}Editar perfil</button>
      </div>
    </header>

    <section class="section">
      <div class="mood">
        <div class="t-kicker">Tu mood</div>
        <div class="t-h2" style="margin-top:4px">${esc(p.moodLabel || "Explorando sonidos")}</div>
        ${(p.moodTags || []).length ? `<div class="tags" style="margin-top:var(--s-3)">${p.moodTags.slice(0, 10).map((t) => `<span class="tag">${esc(t)}</span>`).join("")}</div>` : ""}
        ${(p.badges || []).length ? `<div class="tags" style="margin-top:var(--s-2)">${p.badges.slice(0, 8).map((b) => `<span class="tag tag--beef">${icon("trophy", "icon--sm")}${esc(b.label || "")}</span>`).join("")}</div>` : ""}
      </div>
      <div class="stats" style="margin-top:var(--s-2)">
        <div class="stat"><div class="stat__label">Votos</div><div class="stat__value">${num(p.totalVotes)}</div></div>
        <div class="stat"><div class="stat__label">Likes</div><div class="stat__value">${num(p.totalLikes)}</div></div>
        <div class="stat"><div class="stat__label">Dislikes</div><div class="stat__value">${num(p.totalDislikes)}</div></div>
        <div class="stat"><div class="stat__label">Toxicidad</div><div class="stat__value">${num(p.toxicity)}%</div></div>
      </div>
    </section>

    <section class="section" aria-labelledby="genres-title">
      <div class="section__head"><h2 class="t-h2" id="genres-title">Tus géneros</h2>${p.dominantGenre ? `<span class="t-meta">Dominante: <strong class="text-strong">${esc(p.dominantGenre)}</strong></span>` : ""}</div>
      ${genresHtml(Array.isArray(p.genres) ? p.genres : [])}
    </section>

    <section class="section" aria-labelledby="achv-title">
      <div class="section__head"><h2 class="t-h2" id="achv-title">Logros</h2><span class="t-meta tabular">${unlockedN}/${all.length}</span></div>
      <div class="xp" style="margin-bottom:var(--s-4)" aria-hidden="true"><span style="--v:${Math.round((unlockedN / all.length) * 100)}%"></span></div>
      <div class="achv-tools">
        <label class="search">${icon("search", "icon--sm")}<span class="sr-only">Buscar logro</span><input id="achv-search" type="search" value="${esc(achv.q)}" placeholder="Buscar logro (drill, likes, votos…)" autocomplete="off" /></label>
        <div class="achv-tools__row">
          <div class="segmented" role="tablist" aria-label="Filtrar logros">
            <button role="tab" data-filter="all" aria-selected="${achv.filter === "all"}">Todos</button>
            <button role="tab" data-filter="unlocked" aria-selected="${achv.filter === "unlocked"}">Conseguidos</button>
            <button role="tab" data-filter="locked" aria-selected="${achv.filter === "locked"}">Pendientes</button>
          </div>
          <label class="sr-only" for="achv-sort">Ordenar logros</label>
          <select class="select" id="achv-sort">
            <option value="smart">Más cerca primero</option>
            <option value="progress">Por progreso</option>
            <option value="unlocked-first">Conseguidos primero</option>
            <option value="az">A → Z</option>
          </select>
        </div>
      </div>
      <div class="achv-grid" id="achv-grid"></div>
    </section>

    ${settingsHtml(true)}
  `;

  const grid = root.querySelector("#achv-grid");
  const paintAchv = () => {
    const q = achv.q.toLowerCase();
    const list = all
      .filter((a) => (achv.filter === "unlocked" ? a.unlocked : achv.filter === "locked" ? !a.unlocked : true))
      .filter((a) => !q || `${a.title} ${a.desc} ${a.genre || ""}`.toLowerCase().includes(q))
      .sort(SORTS[achv.sort] || SORTS.smart);
    grid.innerHTML = achievementsHtml(list);
  };
  const sortEl = root.querySelector("#achv-sort");
  sortEl.value = achv.sort;
  sortEl.addEventListener("change", () => { achv.sort = sortEl.value; paintAchv(); });
  root.querySelector("#achv-search").addEventListener("input", debounce((e) => { achv.q = e.target.value.trim(); paintAchv(); }, 120));
  root.querySelectorAll("[data-filter]").forEach((b) => b.addEventListener("click", () => {
    achv.filter = b.dataset.filter;
    root.querySelectorAll("[data-filter]").forEach((o) => o.setAttribute("aria-selected", String(o === b)));
    paintAchv();
  }));
  paintAchv();
}

async function load(root) {
  root.innerHTML = `
    <header class="level-hero" aria-busy="true">
      <div class="level-hero__top"><div class="skel" style="width:88px;height:88px;border-radius:50%"></div><div style="display:grid;gap:8px;flex:1"><div class="skel" style="height:12px;width:90px"></div><div class="skel" style="height:30px;width:60%"></div></div></div>
      <div class="skel" style="height:8px"></div>
    </header>
    <div class="stats" style="margin-top:var(--s-6)">${'<div class="skel" style="height:84px"></div>'.repeat(4)}</div>`;
  try {
    const [p, me] = await Promise.all([usersApi.soundProfile(), getMe().catch(() => null)]);
    if (root.isConnected) render(root, p, me);
  } catch (err) {
    root.innerHTML = `
      <header class="view-head"><p class="t-kicker">Tu cuenta</p><h1 class="t-h1">Perfil sonoro</h1></header>
      ${`<div class="empty">${icon("alert")}<div class="t-ui" style="color:var(--text)">No se pudo cargar tu perfil</div><div class="t-meta">${esc(err.status === 401 ? "Tu sesión ha caducado. Vuelve a entrar." : err.message)}</div>${err.status === 401 ? `<button class="btn btn--sm" data-action="logout">Volver a entrar</button>` : `<button class="btn btn--sm" data-action="reload-profile">Reintentar</button>`}</div>`}
      ${settingsHtml(true)}`;
    root.querySelector("[data-action='reload-profile']")?.addEventListener("click", () => load(root));
  }
}

export const profileView = {
  title: "Perfil sonoro",
  mount(root) {
    if (!auth.isLogged()) {
      root.innerHTML = guestHtml();
      return;
    }
    load(root);
    return onMeChange(() => load(root));
  },
};
