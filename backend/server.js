require("dotenv").config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors());
app.use(express.json());

// === SUPABASE ===
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// === AUTH ADMIN ===
function crearTokenAdmin() {
  const payload = { role: "admin" };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
}

// === AUTH USER ===
function crearTokenUser(user) {
  const payload = {
    role: "user",
    userId: user.id,
    username: user.username,
  };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
}

function authUser(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: "No autorizado" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "user") {
      return res.status(403).json({ error: "Permisos insuficientes" });
    }
    req.user = decoded;
    next();
  } catch (err) {
    console.error("Error verificando token user:", err.message);
    return res.status(401).json({ error: "Token no válido o expirado" });
  }
}

function authAdmin(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: "No autorizado" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "admin") {
      return res.status(403).json({ error: "Permisos insuficientes" });
    }
    next();
  } catch (err) {
    console.error("Error verificando token admin:", err.message);
    return res.status(401).json({ error: "Token no válido o expirado" });
  }
}

// === AUTH USER OPCIONAL (para /api/canciones) ===
function getUserFromToken(req) {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
        ? authHeader.slice(7)
        : null;

    if (!token) return null;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== "user") return null;
        // decoded tiene: role, userId, username
        return decoded;
    } catch (err) {
        console.error("Error verificando token opcional:", err.message);
        return null;
    }
}

// === DISCORD WEBHOOK ===
async function enviarAPeticionDiscord({ nick, style, idea, idPeticion }) {
  const url = process.env.DISCORD_WEBHOOK_URL;
  if (!url) return;

  const content =
    `🎵 **Nueva petición de canción**\n` +
    `👤 Nick: ${nick}\n` +
    `🎧 Estilo: ${style}\n` +
    `📝 Idea:\n${idea}\n\n` +
    `🆔 ID petición: ${idPeticion}`;

  await axios.post(url, { content });
}

// === RUTA TEST ===
app.get("/", (req, res) => {
  res.send("API BeefMusic funcionando");
});

// === LOGIN ADMIN ===
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  if (
    username === process.env.ADMIN_USER &&
    password === process.env.ADMIN_PASS
  ) {
    const token = crearTokenAdmin();
    return res.json({ token });
  }

  return res.status(401).json({ error: "Credenciales incorrectas" });
});

// === REGISTRO USUARIO NORMAL ===
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Faltan campos" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "La contraseña debe tener al menos 6 caracteres" });
    }

    // ¿ya existe?
    const { data: existente, error: errorCheck } = await supabase
      .from("usuarios")
      .select("id")
      .eq("username", username)
      .maybeSingle();

    if (errorCheck && errorCheck.code !== "PGRST116") {
      console.error("Supabase error (check user):", errorCheck);
      return res
        .status(500)
        .json({ error: "Error comprobando usuario existente" });
    }

    if (existente) {
      return res.status(400).json({ error: "Ese usuario ya existe" });
    }

    const password_hash = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from("usuarios")
      .insert({ username, password_hash })
      .select()
      .single();

    if (error) {
      console.error("Supabase error (insert user):", error);
      return res.status(500).json({ error: "Error creando el usuario" });
    }

    const token = crearTokenUser(data);

    res.status(201).json({
      message: "Usuario registrado correctamente",
      token,
      username: data.username,
    });
  } catch (err) {
    console.error("Error en POST /api/register:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// === LOGIN USUARIO NORMAL ===
app.post("/api/login-user", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Faltan campos" });
    }

    const { data: user, error } = await supabase
      .from("usuarios")
      .select("id, username, password_hash")
      .eq("username", username)
      .maybeSingle();

    if (error && error.code !== "PGRST116") {
      console.error("Supabase error (login user):", error);
      return res.status(500).json({ error: "Error buscando usuario" });
    }

    if (!user) {
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }

    const token = crearTokenUser(user);

    res.json({
      message: "Login correcto",
      token,
      username: user.username,
    });
  } catch (err) {
    console.error("Error en POST /api/login-user:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// === CREAR PETICIÓN (PÚBLICO) ===
app.post("/api/peticiones", async (req, res) => {
  try {
    const { nick, style, idea } = req.body;

    if (!nick || !style || !idea) {
      return res.status(400).json({ error: "Faltan campos obligatorios" });
    }

    const { data, error } = await supabase
      .from("peticiones")
      .insert({
        nick,
        estilo: style,
        idea,
        // estado: "pendiente", si no lo tienes como default en la tabla
      })
      .select()
      .single();

    if (error) {
      console.error("Supabase error (insert peticion):", error);
      return res.status(500).json({ error: "Error guardando la petición" });
    }

    const idPeticion = data.id;

    try {
      await enviarAPeticionDiscord({ nick, style, idea, idPeticion });
    } catch (err) {
      console.error("Error enviando a Discord:", err.message);
    }

    res.status(201).json({
      message: "Petición creada correctamente",
      id: idPeticion,
    });
  } catch (error) {
    console.error("Error en POST /api/peticiones:", error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// === LISTAR PETICIONES (ADMIN) ===
app.get("/api/peticiones", authAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("peticiones")
      .select("id, nick, estilo, idea, estado, created_at")
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Supabase error (select peticiones):", error);
      return res
        .status(500)
        .json({ error: "Error al obtener las peticiones" });
    }

    res.json(data);
  } catch (error) {
    console.error("Error en GET /api/peticiones:", error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// === ACTUALIZAR ESTADO DE UNA PETICIÓN (ADMIN) ===
app.patch("/api/peticiones/:id/estado", authAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { estado } = req.body;

    const estadosPermitidos = ["pendiente", "en_produccion", "terminada"];

    if (!estadosPermitidos.includes(estado)) {
      return res.status(400).json({
        error: "Estado no válido. Usa: pendiente, en_produccion o terminada",
      });
    }

    const { data, error } = await supabase
      .from("peticiones")
      .update({ estado })
      .eq("id", id)
      .select("id, estado")
      .single();

    if (error) {
      console.error("Supabase error (update estado):", error);
      return res
        .status(500)
        .json({ error: "Error al actualizar el estado de la petición" });
    }

    res.json({
      message: "Estado actualizado correctamente",
      peticion: data,
    });
  } catch (error) {
    console.error("Error en PATCH /api/peticiones/:id/estado:", error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// === LISTAR CANCIONES (PÚBLICO, CON LIKES/DISLIKES Y VOTO DEL USUARIO) ===
app.get("/api/canciones", async (req, res) => {
    try {
        // usuario opcional (si hay token, lo usamos; si no, null)
        const user = getUserFromToken(req);
        const userId = user ? user.userId : null;

        // 1) Canciones base
        const { data: canciones, error: errorCanciones } = await supabase
            .from("canciones")
            .select(
                "id, titulo, estilo, duracion, descripcion, autor, estado, url_audio, created_at"
            )
            .order("created_at", { ascending: false });

        if (errorCanciones) {
            console.error("Supabase error (select canciones):", errorCanciones);
            return res
                .status(500)
                .json({ error: "Error al obtener las canciones" });
        }

        if (!canciones || canciones.length === 0) {
            return res.json([]);
        }

        // 2) Todos los votos (para agregarlos en Node)
        let votos = [];
        const { data: votosData, error: errorVotos } = await supabase
            .from("votos_cancion")
            .select("id, cancion_id, usuario_id, tipo");

        if (errorVotos) {
            // Si peta, mostramos canciones sin votos en vez de reventar todo
            console.error("Supabase error (select votos_cancion):", errorVotos);
            votos = [];
        } else {
            votos = votosData || [];
        }

        // 3) Agrupar votos por canción para contar likes y dislikes
        const votesBySong = new Map();
        for (const v of votos) {
            const list = votesBySong.get(v.cancion_id) || [];
            list.push(v);
            votesBySong.set(v.cancion_id, list);
        }

        // 4) Construir respuesta con likes, dislikes y userVote
        const respuesta = canciones.map((c) => {
            const songVotes = votesBySong.get(c.id) || [];

            let likes = 0;
            let dislikes = 0;
            let userVote = null;

            for (const v of songVotes) {
                if (v.tipo === "like") likes++;
                if (v.tipo === "dislike") dislikes++;
                if (userId && v.usuario_id === userId) {
                    userVote = v.tipo; // 'like' o 'dislike'
                }
            }

            return {
                id: c.id,
                titulo: c.titulo,
                estilo: c.estilo,
                duracion: c.duracion,
                descripcion: c.descripcion,
                autor: c.autor,
                estado: c.estado,
                url_audio: c.url_audio,
                created_at: c.created_at,
                likes,
                dislikes,
                userVote, // puede ser 'like', 'dislike' o null
            };
        });

        res.json(respuesta);
    } catch (err) {
        console.error("Error en GET /api/canciones:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === VOTAR CANCIÓN (like / dislike, 1 voto por usuario) ===
app.post("/api/canciones/:id/vote", authUser, async (req, res) => {
    try {
        const { id } = req.params;
        const { tipo } = req.body; // 'like' o 'dislike'
        const userId = req.user.userId;

        if (tipo !== "like" && tipo !== "dislike") {
            return res
                .status(400)
                .json({ error: "Tipo de voto no válido. Usa 'like' o 'dislike'." });
        }

        // Comprobar que la canción existe
        const { data: song, error: errorSong } = await supabase
            .from("canciones")
            .select("id")
            .eq("id", id)
            .maybeSingle();

        if (errorSong) {
            console.error("Supabase error (select cancion en voto):", errorSong);
            return res
                .status(500)
                .json({ error: "Error buscando la canción" });
        }

        if (!song) {
            return res.status(404).json({ error: "Canción no encontrada" });
        }

        // 1) Ver si ya hay un voto de este usuario para esta canción
        const { data: existingVote, error: errorExisting } = await supabase
            .from("votos_cancion")
            .select("id, tipo")
            .eq("cancion_id", id)
            .eq("usuario_id", userId)
            .maybeSingle();

        if (errorExisting && errorExisting.code !== "PGRST116") {
            console.error("Supabase error (select voto existente):", errorExisting);
            return res
                .status(500)
                .json({ error: "Error comprobando voto existente" });
        }

        // 2) Insertar o actualizar voto
        if (!existingVote) {
            // No había voto -> insert
            const { error: errorInsert } = await supabase
                .from("votos_cancion")
                .insert({
                    cancion_id: id,
                    usuario_id: userId,
                    tipo,
                });

            if (errorInsert) {
                console.error("Supabase error (insert voto):", errorInsert);
                return res
                    .status(500)
                    .json({ error: "Error guardando el voto" });
            }
        } else if (existingVote.tipo !== tipo) {
            // Había voto distinto -> actualizar tipo
            const { error: errorUpdateVote } = await supabase
                .from("votos_cancion")
                .update({ tipo })
                .eq("id", existingVote.id);

            if (errorUpdateVote) {
                console.error("Supabase error (update voto):", errorUpdateVote);
                return res
                    .status(500)
                    .json({ error: "Error actualizando el voto" });
            }
        } else {
            // Ya había un voto igual -> no hacemos nada, devolvemos contadores
            console.log(
                `Usuario ${userId} ya tenía voto '${tipo}' en canción ${id}, no se cambia.`
            );
        }

        // 3) Recalcular likes/dislikes de esa canción
        const { data: votosSong, error: errorCounts } = await supabase
            .from("votos_cancion")
            .select("tipo")
            .eq("cancion_id", id);

        if (errorCounts) {
            console.error("Supabase error (contar votos):", errorCounts);
            return res
                .status(500)
                .json({ error: "Error obteniendo los votos actualizados" });
        }

        let likes = 0;
        let dislikes = 0;

        (votosSong || []).forEach((v) => {
            if (v.tipo === "like") likes++;
            if (v.tipo === "dislike") dislikes++;
        });

        res.json({
            message: "Voto registrado",
            likes,
            dislikes,
            userVote: tipo,
        });
    } catch (err) {
        console.error("Error en POST /api/canciones/:id/vote:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === CREAR CANCIÓN (ADMIN) ===
app.post("/api/canciones", authAdmin, async (req, res) => {
  try {
    const {
      titulo,
      estilo,
      duracion,
      descripcion,
      autor,
      estado = "publicada",
      url_audio,
    } = req.body;

    if (!titulo || !estilo || !autor) {
      return res.status(400).json({ error: "Faltan campos obligatorios" });
    }

    const { data, error } = await supabase
      .from("canciones")
      .insert({
        titulo,
        estilo,
        duracion,
        descripcion,
        autor,
        estado,
        url_audio,
      })
      .select()
      .single();

    if (error) {
      console.error("Supabase error (insert cancion):", error);
      return res.status(500).json({ error: "Error creando la canción" });
    }

    res.status(201).json({
      message: "Canción creada correctamente",
      cancion: data,
    });
  } catch (err) {
    console.error("Error en POST /api/canciones:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`BeefMusic API escuchando en http://localhost:${port}`);
});
