// Catálogo fijo de 100 logros (mismo que el perfil sonoro antiguo) y su progreso.

const n = (v) => (typeof v === "number" && Number.isFinite(v) ? v : 0);

function buildCatalog() {
  const list = [];
  let id = 1;
  const push = (o) => list.push({ ...o, id: "A" + String(id++).padStart(3, "0") });

  [1, 2, 3, 5, 8, 10, 12, 15, 18, 20, 25, 30, 35, 40, 45, 50, 60, 70, 80, 90, 100, 125, 150, 175, 200].forEach((t) =>
    push({ icon: "check", title: `Votante ${t}+`, desc: `Alcanza ${t} votos totales.`, type: "totalVotes", target: t })
  );
  [1, 2, 3, 5, 8, 10, 12, 15, 18, 20, 25, 30, 35, 40, 45, 50, 60, 70, 80, 90, 100, 120, 140, 160, 180].forEach((t) =>
    push({ icon: "up", title: `Coleccionista de bangers ${t}+`, desc: `Consigue ${t} likes totales.`, type: "totalLikes", target: t })
  );
  [1, 2, 3, 5, 8, 10, 12, 15, 18, 20, 25, 30, 40, 50, 75].forEach((t) =>
    push({ icon: "down", title: `Hater con criterio ${t}+`, desc: `Da ${t} dislikes totales.`, type: "totalDislikes", target: t })
  );
  [5, 10, 15, 20, 30, 40, 50, 60, 70, 80].forEach((t) =>
    push({ icon: "flame", title: `Toxicidad ${t}%`, desc: `Alcanza ${t}% de toxicidad (dislikes/votos).`, type: "toxicity", target: t })
  );
  const genres = ["Trap", "Drill", "Dembow", "Boom Bap", "Phonk", "Corridos tumbados", "Afrobeat", "Dancehall", "R&B", "Reggaetón", "Rap", "Pop urbano"];
  genres.forEach((g) =>
    [5, 20].forEach((t) =>
      push({ icon: "music", title: `${t} likes en ${g}`, desc: `Consigue ${t} likes en ${g}.`, type: "genreLikes", genre: g, target: t })
    )
  );
  push({ icon: "sparkles", title: "Explorador de estilos", desc: "Vota en 5 géneros distintos.", type: "genreDiversity", target: 5 });
  return list.slice(0, 100);
}

export const ACHIEVEMENTS = buildCatalog();

function genreVotes(profile, name) {
  const g = (profile.genres || []).find((x) => (x.name || "").toLowerCase() === name.toLowerCase());
  return g ? { likes: n(g.likes), dislikes: n(g.dislikes) } : { likes: 0, dislikes: 0 };
}

function progressFor(profile, a) {
  switch (a.type) {
    case "totalVotes": return n(profile.totalVotes);
    case "totalLikes": return n(profile.totalLikes);
    case "totalDislikes": return n(profile.totalDislikes);
    case "toxicity": return n(profile.toxicity);
    case "genreLikes": return genreVotes(profile, a.genre).likes;
    case "genreDiversity": return (profile.genres || []).filter((g) => n(g.likes) + n(g.dislikes) > 0).length;
    default: return 0;
  }
}

// Devuelve cada logro con su progreso calculado.
export function evaluate(profile) {
  return ACHIEVEMENTS.map((a) => {
    const target = Math.max(1, a.target);
    const current = progressFor(profile, a);
    return { ...a, current, target, ratio: Math.min(1, current / target), unlocked: current >= target };
  });
}

export const SORTS = {
  smart: (x, y) => (x.unlocked === y.unlocked ? y.ratio - x.ratio : x.unlocked ? 1 : -1),
  progress: (x, y) => y.ratio - x.ratio,
  "unlocked-first": (x, y) => (x.unlocked === y.unlocked ? 0 : x.unlocked ? -1 : 1),
  az: (x, y) => x.title.localeCompare(y.title, "es", { sensitivity: "base" }),
};
