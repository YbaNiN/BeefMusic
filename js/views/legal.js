// Vistas legales (#/terminos, #/privacidad). El texto vive en content/*.html
// para poder editarlo sin tocar código; aquí se le añade índice y progreso.
import { esc, icon } from "../dom.js";
import { emptyState } from "../song-ui.js";

const cache = new Map();

async function loadContent(name) {
  if (!cache.has(name)) {
    cache.set(
      name,
      fetch(`content/${name}.html`).then((r) => {
        if (!r.ok) throw new Error("No se encontró el texto.");
        return r.text();
      })
    );
  }
  try {
    return await cache.get(name);
  } catch (err) {
    cache.delete(name);
    throw err;
  }
}

function scrollToSection(root, id) {
  const el = id && root.querySelector(`#legal-${CSS.escape(id)}`);
  if (!el) return;
  el.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  el.querySelector("h2")?.setAttribute("tabindex", "-1");
  el.querySelector("h2")?.focus({ preventScroll: true });
}

function makeLegalView(name, title) {
  return {
    title,
    async mount(root, params) {
      root.innerHTML = `<div class="legal-loading" aria-busy="true">${'<div class="skel" style="height:14px"></div>'.repeat(8)}</div>`;
      let html;
      try {
        html = await loadContent(name);
      } catch (err) {
        root.innerHTML = emptyState("alert", "No se pudo cargar el texto", err.message, `<a class="btn btn--sm" href="#/${name}">Reintentar</a>`);
        return;
      }
      if (!root.isConnected) return;

      root.innerHTML = `
        <div class="legal-progress" aria-hidden="true"><span id="legal-progress"></span></div>
        <div class="legal-layout">
          <article class="legal" id="legal-article">${html}</article>
          <aside class="legal-aside" aria-label="Índice">
            <details class="legal-toc" id="legal-toc" open>
              <summary><span class="t-kicker">Índice</span>${icon("chevron-down", "icon--sm")}</summary>
              <nav><ol id="legal-toc-list"></ol></nav>
            </details>
            <div class="legal-aside__links">
              ${name === "terminos" ? `<a class="btn btn--sm btn--outline" href="#/privacidad">Privacidad</a>` : `<a class="btn btn--sm btn--outline" href="#/terminos">Términos</a>`}
              <a class="btn btn--sm btn--outline" href="#/contacto">Contacto</a>
            </div>
          </aside>
        </div>`;

      const article = root.querySelector("#legal-article");
      const sections = [...article.querySelectorAll(".legal-section[id]")];
      root.querySelector("#legal-toc-list").innerHTML = sections
        .map((s) => {
          const id = s.id.replace(/^legal-/, "");
          return `<li><a href="#/${name}?s=${esc(id)}" data-toc="${esc(id)}">${esc(s.querySelector("h2")?.textContent || id)}</a></li>`;
        })
        .join("");

      // En móvil el índice empieza plegado.
      const toc = root.querySelector("#legal-toc");
      if (matchMedia("(max-width: 1023px)").matches) toc.open = false;

      // Progreso de lectura + sección actual en el índice.
      const bar = root.querySelector("#legal-progress");
      const main = document.getElementById("main");
      const scroller = () => (matchMedia("(min-width: 1024px)").matches ? main : document.documentElement);
      const onScroll = () => {
        const s = scroller();
        const rect = article.getBoundingClientRect();
        const viewH = s === main ? main.clientHeight : innerHeight;
        const total = article.offsetHeight - viewH * 0.6;
        const read = Math.min(1, Math.max(0, (-rect.top + 120) / Math.max(1, total)));
        bar.style.transform = `scaleX(${read})`;
      };
      const io = new IntersectionObserver(
        (entries) => {
          entries.forEach((en) => {
            if (!en.isIntersecting) return;
            const id = en.target.id.replace(/^legal-/, "");
            root.querySelectorAll("[data-toc]").forEach((a) => a.toggleAttribute("aria-current", a.dataset.toc === id));
          });
        },
        { rootMargin: "-20% 0px -70% 0px" }
      );
      sections.forEach((s) => io.observe(s));
      window.addEventListener("scroll", onScroll, { passive: true });
      main.addEventListener("scroll", onScroll, { passive: true });
      onScroll();

      if (params.s) requestAnimationFrame(() => scrollToSection(root, params.s));

      // Clic en el índice o en un enlace interno: mover sin recargar la vista.
      this.update = (p) => {
        if (p.s) scrollToSection(root, p.s);
        if (matchMedia("(max-width: 1023px)").matches) toc.open = false;
      };

      return () => {
        this.update = null;
        io.disconnect();
        window.removeEventListener("scroll", onScroll);
        main.removeEventListener("scroll", onScroll);
      };
    },
    update: null,
  };
}

export const termsView = makeLegalView("terminos", "Términos de uso");
export const privacyView = makeLegalView("privacidad", "Política de privacidad");
