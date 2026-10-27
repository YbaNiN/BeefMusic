// Piezas HTML de usuario: avatar con foto opcional, enlaces sociales, niveles.
import { esc, icon } from "./dom.js";

export function safeHttpUrl(value) {
  try {
    const u = new URL(String(value || "").trim());
    return u.protocol === "http:" || u.protocol === "https:" ? u.toString() : "";
  } catch {
    return "";
  }
}

// Inicial siempre debajo; si la foto carga, la tapa. Si falla, se quita.
export function avatarHtml(name, url = "", size = "") {
  const initial = esc(String(name || "?").charAt(0).toUpperCase());
  const src = safeHttpUrl(url);
  const img = src ? `<img src="${esc(src)}" alt="" loading="lazy" referrerpolicy="no-referrer" onerror="this.remove()">` : "";
  return `<span class="avatar ${size}" aria-hidden="true">${initial}${img}</span>`;
}

export const SOCIALS = [
  ["instagram", "Instagram"],
  ["youtube", "YouTube"],
  ["soundcloud", "SoundCloud"],
  ["spotify", "Spotify"],
];

export function socialLinks(links = {}) {
  return SOCIALS.map(([key, label]) => {
    const url = safeHttpUrl(links[key]);
    return url ? `<a class="btn btn--outline btn--sm" href="${esc(url)}" target="_blank" rel="noopener nofollow">${label}${icon("external", "icon--sm")}</a>` : "";
  }).join("");
}

// Mismo modelo de niveles que el perfil sonoro antiguo (por si el backend no lo manda).
export function levelFromXp(xp) {
  let level = 1;
  let remaining = Math.max(0, Number(xp) || 0);
  let cost = 20;
  while (remaining >= cost && level < 100) {
    remaining -= cost;
    level += 1;
    cost = Math.round(20 + level * 6);
  }
  return { level, xpIntoLevel: remaining, xpForNextLevel: cost };
}

export function titleForLevel(level) {
  const table = [
    [1, "Beef Rookie"], [5, "Beat Hunter"], [10, "Hook Crafter"], [15, "Flow Engineer"],
    [20, "Studio Menace"], [30, "Mix & Mayhem"], [40, "Neon Producer"], [50, "Boss del Bloque"],
    [65, "Leyenda del Server"], [80, "Final Boss"], [95, "BeefMusic Godmode"],
  ];
  let title = table[0][1];
  for (const [min, t] of table) if (level >= min) title = t;
  return title;
}
