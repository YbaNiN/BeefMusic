// Cliente del backend. Mismos endpoints y cuerpos que usaban las páginas antiguas.
import { API_URL, TOKEN_KEY, USER_KEY } from "./config.js";

export const auth = {
  token: () => localStorage.getItem(TOKEN_KEY) || "",
  user: () => (localStorage.getItem(USER_KEY) || "").replace(/^@/, ""),
  isLogged() {
    return Boolean(this.token());
  },
  logout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    location.href = "user-login.html";
  },
};

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

export async function api(path, { method = "GET", body, withAuth = true } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const token = auth.token();
  if (withAuth && token) headers.Authorization = "Bearer " + token;

  let res;
  try {
    res = await fetch(API_URL + path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError("No hay conexión con el servidor de BeefMusic.", 0);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok || (data && data.error && method !== "GET")) {
    throw new ApiError((data && data.error) || `Error ${res.status}`, res.status);
  }
  return data;
}

/* ---------- Canciones, votos y comentarios ---------- */
export const songsApi = {
  list: () => api("/api/canciones"),
  vote: (id, tipo) => api(`/api/canciones/${encodeURIComponent(id)}/vote`, { method: "POST", body: { tipo } }),
  commentsTree: (id) =>
    api(`/api/canciones/${encodeURIComponent(id)}/comments-tree?limit=50&offset=0&maxTotal=1200`, { withAuth: false }),
  comment: (id, text, parentId = null) =>
    api(`/api/canciones/${encodeURIComponent(id)}/comments`, { method: "POST", body: { body: text, parentId } }),
  reportComment: (commentId, reason) =>
    api("/api/report/content", { method: "POST", body: { targetType: "comment", targetId: commentId, reason: reason.slice(0, 500) } }),
};

/* ---------- Peticiones, sugerencias, reportes, asistente ---------- */
export const sendRequest = (data) => api("/api/peticiones", { method: "POST", body: data });
export const sendSuggestion = (data) => api("/api/sugerencias", { method: "POST", body: data });
export const sendReport = (data) => api("/api/reportes", { method: "POST", body: data });
export const askAssistant = (prompt) => api("/api/assistant", { method: "POST", body: { prompt } });

// Listado público (sin el texto de la petición). estilo = coincidencia exacta.
export function publicRequests({ estado = "", estilo = "", limit = 24, offset = 0 } = {}) {
  const q = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (estado) q.set("estado", estado);
  if (estilo) q.set("estilo", estilo);
  return api("/api/peticiones-publicas?" + q.toString(), { withAuth: false });
}

// Cuenta todas las peticiones públicas paginando, igual que la portada antigua.
export async function countPublicRequests({ pageSize = 100, maxPages = 60 } = {}) {
  let offset = 0;
  let total = 0;
  for (let i = 0; i < maxPages; i++) {
    const data = await api(`/api/peticiones-publicas?limit=${pageSize}&offset=${offset}`, { withAuth: false });
    if (!Array.isArray(data)) throw new ApiError("La API de peticiones no devolvió lista", 500);
    total += data.length;
    if (data.length < pageSize) return { total, capped: false };
    offset += pageSize;
  }
  return { total: maxPages * pageSize, capped: true };
}

/* ---------- Usuarios, seguir, feed y perfil sonoro ---------- */
export const usersApi = {
  get: (username) => api(`/api/users/${encodeURIComponent(username)}`),
  follow: (userId) => api(`/api/users/${encodeURIComponent(userId)}/follow`, { method: "POST" }),
  unfollow: (userId) => api(`/api/users/${encodeURIComponent(userId)}/follow`, { method: "DELETE" }),
  // El backend espera { bio, avatarUrl, links, isPublic } (camelCase).
  updateMe: (data) => api("/api/users/me/profile", { method: "PATCH", body: data }),
  feed: (offset = 0, limit = 20) => api(`/api/feed?limit=${limit}&offset=${offset}`),
  soundProfile: () => api("/api/sound-profile"),
};

/* ---------- Notificaciones ---------- */
export const notificationsApi = {
  list: (params) => api("/api/notifications?" + new URLSearchParams(params).toString()),
  readAll: () => api("/api/notifications/read-all", { method: "POST" }),
  read: (id) => api(`/api/notifications/${encodeURIComponent(id)}/read`, { method: "PATCH" }),
};
