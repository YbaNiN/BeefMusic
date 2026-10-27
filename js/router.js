// Enrutado por hash: #/  #/canciones  #/canciones?song=12  #/comunidad  #/perfil
import { $$ } from "./dom.js";

const routes = new Map();
let cleanup = null;
let currentName = null;

export function defineRoute(name, view) {
  routes.set(name, view);
}

export function parseHash(hash = location.hash) {
  const raw = hash.replace(/^#\/?/, "");
  const [path, query = ""] = raw.split("?");
  const [name, ...rest] = path.split("/");
  const params = Object.fromEntries(new URLSearchParams(query));
  // #/u/usuario → perfil público
  if (rest.length) params.path = decodeURIComponent(rest.join("/"));
  return { name: name || "inicio", params };
}

export function navigate(name, params = {}) {
  const q = new URLSearchParams(params).toString();
  location.hash = "#/" + (name === "inicio" ? "" : name) + (q ? "?" + q : "");
}

// Cambia la URL sin volver a pintar la vista (p. ej. al abrir una canción).
export function replaceParams(params = {}) {
  const { name } = parseHash();
  const q = new URLSearchParams(params).toString();
  history.replaceState(history.state, "", "#/" + (name === "inicio" ? "" : name) + (q ? "?" + q : ""));
}

async function render() {
  const { name, params } = parseHash();
  const view = routes.get(name) || routes.get("inicio");
  const target = document.getElementById("view");

  // Misma vista y solo cambian parámetros (no la ruta): la vista decide.
  const key = name + "/" + (params.path || "");
  if (currentName === key && view.update) {
    view.update(params);
    return;
  }

  if (typeof cleanup === "function") cleanup();
  cleanup = null;
  currentName = key;

  const navKey = view.nav || name;
  $$("[data-nav]").forEach((a) => {
    if (a.dataset.nav === navKey) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });

  const title = typeof view.title === "function" ? view.title(params) : view.title;
  document.title = title ? `${title} · BeefMusic` : "BeefMusic";
  target.innerHTML = "";
  target.classList.remove("view-enter");
  void target.offsetWidth;
  target.classList.add("view-enter");

  // Volver arriba: en móvil se desplaza la ventana, en escritorio el panel.
  window.scrollTo(0, 0);
  const main = document.getElementById("main");
  if (main) main.scrollTop = 0;

  cleanup = (await view.mount(target, params)) || null;
  const h1 = target.querySelector("h1");
  if (h1 && document.activeElement === document.body) {
    h1.setAttribute("tabindex", "-1");
  }
}

export function startRouter() {
  window.addEventListener("hashchange", render);
  render();
}
