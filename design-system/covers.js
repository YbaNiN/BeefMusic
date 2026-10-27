/* ==========================================================================
   BeefMusic · Portadas generadas
   Las canciones no tienen imagen en la base de datos, así que cada portada
   se genera a partir del id/título (siempre la misma para la misma canción)
   y se tiñe con el color de su género.

   Uso:
     BeefCover.paint(el, { id, titulo, estilo })
     BeefCover.html({ id, titulo, estilo }, "cover--lg")  → string HTML
   ========================================================================== */
(function () {
  // Tono base por género (grados HSL). Lo que no encaje usa el hash.
  const GENRE_HUES = [
    [/trap/i, 265],
    [/drill/i, 200],
    [/dembow/i, 24],
    [/regg?a?et[oó]n|perreo/i, 325],
    [/boom ?bap|rap/i, 40],
    [/salsa|cumbia|bachata|latin/i, 145],
    [/r&b|rnb|soul/i, 290],
    [/pop/i, 345],
    [/rkt|guaracha|electr/i, 180],
  ];

  const VARIANTS = ["mesh", "vinyl", "type", "split"];

  function hash(str) {
    let h = 2166136261;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }

  function hueFor(estilo, h) {
    for (const [re, hue] of GENRE_HUES) if (re.test(estilo || "")) return hue;
    return h % 360;
  }

  function spec(song) {
    const titulo = String(song.titulo || song.title || "Sin título");
    const estilo = String(song.estilo || song.style || "");
    const key = String(song.id ?? "") + "|" + titulo;
    const h = hash(key);
    const base = hueFor(estilo, h);
    const jitter = ((h >> 8) % 37) - 18; // ±18° para que dos trap no sean idénticos
    const hue = (base + jitter + 360) % 360;
    const hue2 = (hue + 28 + ((h >> 16) % 24)) % 360;

    return {
      variant: VARIANTS[(h >>> 23) % VARIANTS.length], // bits altos: reparto más equilibrado
      c1: `hsl(${hue} 88% 60%)`,
      c2: `hsl(${hue2} 82% 48%)`,
      c3: `hsl(${hue} 55% 12%)`,
      tint: `hsl(${hue} 45% 22%)`, // para teñir el mini‑player
      angle: (h >> 4) % 360,
      word: titulo.replace(/[“”"']/g, "").split(/\s+/)[0].slice(0, 9).toUpperCase(),
    };
  }

  function styleString(s) {
    return `--c1:${s.c1};--c2:${s.c2};--c3:${s.c3};--angle:${s.angle}deg`;
  }

  function escape(str) {
    return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  window.BeefCover = {
    spec,
    paint(el, song) {
      const s = spec(song);
      el.classList.add("cover");
      el.dataset.variant = s.variant;
      el.setAttribute("style", styleString(s));
      el.innerHTML = s.variant === "type" ? `<span class="cover__word" aria-hidden="true">${escape(s.word)}</span>` : "";
      return s;
    },
    html(song, extraClass = "") {
      const s = spec(song);
      const inner = s.variant === "type" ? `<span class="cover__word" aria-hidden="true">${escape(s.word)}</span>` : "";
      return `<div class="cover ${extraClass}" data-variant="${s.variant}" style="${styleString(s)}" role="img" aria-label="Portada de ${escape(song.titulo || "la canción")}">${inner}</div>`;
    },
  };
})();
