require("dotenv").config();
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
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

// === DISCORD WEBHOOKS (CONSTANTES GLOBALES) ===
const DISCORD_WEBHOOK_PETICIONES =
    process.env.DISCORD_WEBHOOK_PETICIONES || process.env.DISCORD_WEBHOOK_URL;

const DISCORD_WEBHOOK_SUGERENCIAS =
    process.env.DISCORD_WEBHOOK_SUGERENCIAS || process.env.DISCORD_WEBHOOK_URL;

const DISCORD_WEBHOOK_REPORTES =
    process.env.DISCORD_WEBHOOK_REPORTES || process.env.DISCORD_WEBHOOK_URL;

// === DISCORD: PETICIONES ===
async function enviarAPeticionDiscord({ nick, style, idea, idPeticion }) {
    const url = DISCORD_WEBHOOK_PETICIONES;
    if (!url) return;

    const content =
        `🎵 **Nueva petición de canción**\n` +
        `👤 Nick: ${nick}\n` +
        `🎧 Estilo: ${style}\n` +
        `📝 Idea:\n${idea}\n\n` +
        `🆔 ID petición: ${idPeticion}`;

    await axios.post(url, { content });
}

// === DISCORD: SUGERENCIAS ===
async function enviarASugerenciaDiscord({ nick, mensaje, idSugerencia }) {
    const url = DISCORD_WEBHOOK_SUGERENCIAS;
    if (!url) return;

    const content =
        `💡 **Nueva sugerencia para BeefMusic**\n` +
        `👤 Nick: ${nick || "Anónimo"}\n` +
        `📝 Sugerencia:\n${mensaje}\n\n` +
        `🆔 ID sugerencia: ${idSugerencia}`;

    await axios.post(url, { content });
}

// === DISCORD: REPORTES ===
async function enviarAReporteDiscord({ nick, mensaje, idReporte }) {
    const url = DISCORD_WEBHOOK_REPORTES;
    if (!url) return;

    const content =
        `🐛 **Nuevo reporte de problema en BeefMusic**\n` +
        `👤 Nick: ${nick || "Anónimo"}\n` +
        `📝 Detalle del problema:\n${mensaje}\n\n` +
        `🆔 ID reporte: ${idReporte}`;

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

// === CREAR SUGERENCIA (PÚBLICO) ===
app.post("/api/sugerencias", async (req, res) => {
    try {
        const { nick, mensaje } = req.body;

        if (!mensaje) {
            return res.status(400).json({ error: "Falta el campo 'mensaje' de la sugerencia" });
        }

        const { data, error } = await supabase
            .from("sugerencias")
            .insert({
                nick: nick || null,
                mensaje,
            })
            .select()
            .single();

        if (error) {
            console.error("Supabase error (insert sugerencia):", error);
            return res.status(500).json({ error: "Error guardando la sugerencia" });
        }

        const idSugerencia = data.id;

        try {
            await enviarASugerenciaDiscord({ nick, mensaje, idSugerencia });
        } catch (err) {
            console.error("Error enviando sugerencia a Discord:", err.message);
        }

        res.status(201).json({
            message: "Sugerencia enviada correctamente",
            id: idSugerencia,
        });
    } catch (error) {
        console.error("Error en POST /api/sugerencias:", error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === CREAR REPORTE (PÚBLICO) ===
app.post("/api/reportes", async (req, res) => {
    try {
        const { nick, mensaje } = req.body;

        if (!mensaje) {
            return res.status(400).json({ error: "Falta el campo 'mensaje' del reporte" });
        }

        const { data, error } = await supabase
            .from("reportes")
            .insert({
                nick: nick || null,
                mensaje,
            })
            .select()
            .single();

        if (error) {
            console.error("Supabase error (insert reporte):", error);
            return res.status(500).json({ error: "Error guardando el reporte" });
        }

        const idReporte = data.id;

        try {
            await enviarAReporteDiscord({ nick, mensaje, idReporte });
        } catch (err) {
            console.error("Error enviando reporte a Discord:", err.message);
        }

        res.status(201).json({
            message: "Reporte enviado correctamente",
            id: idReporte,
        });
    } catch (error) {
        console.error("Error en POST /api/reportes:", error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === ASISTENTE IA BEEFMUSIC (USER) ===
// Espera body: { prompt: string }
app.post("/api/assistant", authUser, async (req, res) => {
    try {
        if (!OPENAI_API_KEY) {
            console.error("Falta OPENAI_API_KEY en el .env");
            return res
                .status(500)
                .json({ error: "Configuración de IA no disponible en el servidor" });
        }

        const { prompt } = req.body;

        if (!prompt || typeof prompt !== "string" || !prompt.trim()) {
            return res.status(400).json({ error: "Falta el campo 'prompt'" });
        }

        const username = req.user?.username || "usuario_beefmusic";

        // Llamada al endpoint /v1/responses de OpenAI (API nueva recomendada) :contentReference[oaicite:1]{index=1}
        const openaiResponse = await axios.post(
            "https://api.openai.com/v1/responses",
            {
                model: "gpt-5", // puedes cambiar a otro modelo compatible si quieres
                instructions:
                    "Eres el asistente oficial de BeefMusic. " +
                    "Respondes SIEMPRE en español y estás especializado en música urbana (reggaetón, dembow, trap, drill, rap). " +
                    "Ayudas a componer letras, proponer títulos, estructuras de canciones y planes de lanzamiento en redes. " +
                    "No prometas cosas que el usuario no pueda hacer legalmente (no uses samples con copyright sin permisos, etc.). " +
                    `El usuario actual se llama @${username}.`,
                input: prompt,
                // Opcional: puedes ajustar temperatura, etc.
                // reasoning: { effort: "low" }, // si usas modelos de razonamiento
            },
            {
                headers: {
                    Authorization: `Bearer ${OPENAI_API_KEY}`,
                    "Content-Type": "application/json",
                },
                timeout: 30000,
            }
        );

        // La Responses API expone el texto directamente en output_text cuando el output es texto simple :contentReference[oaicite:2]{index=2}
        const text =
            openaiResponse.data?.output_text ||
            "No he podido generar respuesta en este momento.";

        return res.json({
            ok: true,
            text,
        });
    } catch (err) {
        console.error("Error en POST /api/assistant:", err.response?.data || err.message);

        // Si viene error de OpenAI, intento devolver algo entendible
        if (err.response && err.response.data) {
            return res.status(500).json({
                error: "Error llamando a la IA",
                detail: err.response.data,
            });
        }

        res.status(500).json({ error: "Error en el servidor al usar la IA" });
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

// === VOTAR CANCIÓN (like / dislike, 1 voto por usuario, posibilidad de quitar) ===
app.post("/api/canciones/:id/vote", authUser, async (req, res) => {
    try {
        const { id } = req.params;
        const { tipo } = req.body; // 'like' o 'dislike'
        const userId = req.user.userId; // viene del token (crearTokenUser)

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

        let userVoteResult = null;

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

            userVoteResult = tipo;
        } else if (existingVote.tipo !== tipo) {
            // Había voto distinto -> cambiar tipo
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

            userVoteResult = tipo;
        } else {
            // Ya había un voto igual -> QUITAR voto (toggle off)
            const { error: errorDelete } = await supabase
                .from("votos_cancion")
                .delete()
                .eq("id", existingVote.id);

            if (errorDelete) {
                console.error("Supabase error (delete voto):", errorDelete);
                return res
                    .status(500)
                    .json({ error: "Error eliminando el voto" });
            }

            userVoteResult = null; // sin voto
        }

        // 2) Recalcular likes/dislikes de esa canción
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
            userVote: userVoteResult, // 'like', 'dislike' o null
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

// Normalizar nombres de género (para que "dembow", "Dembow", "DEMBOW" cuenten como uno)
function normalizarGenero(raw) {
    if (!raw) {
        return { key: "desconocido", label: "Desconocido" };
    }

    // quitar espacios, pasar a minúsculas y quitar acentos
    let base = raw.trim().toLowerCase();
    base = base.normalize("NFD").replace(/[\u0300-\u036f]/g, ""); // reggaetón -> reggaeton

    // mapa para nombres bonitos
    const mapa = {
        dembow: "Dembow",
        drill: "Drill",
        trap: "Trap",
        rap: "Rap",
        reggaeton: "Reggaetón",
        pop: "Pop",
        "boom bap": "Boom Bap",       
        "reggaeton_dembow": "Reggaetón / Dembow",
    };

    const label = mapa[base] || (base.charAt(0).toUpperCase() + base.slice(1));

    return { key: base, label };
}


// === PERFIL SONORO DEL USUARIO (USER) ===
app.get("/api/sound-profile", authUser, async (req, res) => {
    try {
        const userId = req.user.userId;
        const username = req.user.username;

        // 1) Votos del usuario
        const { data: votos, error: errorVotos } = await supabase
            .from("votos_cancion")
            .select("tipo, cancion_id")
            .eq("usuario_id", userId);

        if (errorVotos) {
            console.error("Supabase error (select votos usuario):", errorVotos);
            return res.status(500).json({ error: "Error obteniendo votos del usuario" });
        }

        // Si no ha votado nada, devolvemos un perfil vacío pero válido
        if (!votos || votos.length === 0) {
            return res.json({
                username,
                toxicity: 0,
                totalVotes: 0,
                totalLikes: 0,
                totalDislikes: 0,
                genres: [],
                dominantGenre: null,
                moodLabel: "Aún sin datos suficientes",
                moodTags: ["dale like o dislike a alguna canción"],
                badges: [],
            });
        }

        // 2) Sacar los IDs de canciones y traer sus estilos
        const songIds = [...new Set(votos.map((v) => v.cancion_id))];

        const { data: canciones, error: errorCancionesPerfil } = await supabase
            .from("canciones")
            .select("id, estilo")
            .in("id", songIds);

        if (errorCancionesPerfil) {
            console.error("Supabase error (select canciones perfil):", errorCancionesPerfil);
            return res.status(500).json({ error: "Error obteniendo canciones para el perfil" });
        }

        const songMap = new Map();
        (canciones || []).forEach((c) => {
            songMap.set(c.id, c.estilo || "Desconocido");
        });

        // 3) Calcular stats por género + likes/dislikes totales
        const statsByGenre = {};
        let totalVotes = 0;
        let totalLikes = 0;
        let totalDislikes = 0;

        for (const v of votos) {
            const estiloOriginal = songMap.get(v.cancion_id) || "Desconocido";
            const { key, label } = normalizarGenero(estiloOriginal);

            if (!statsByGenre[key]) {
                statsByGenre[key] = { label, likes: 0, dislikes: 0 };
            }

            if (v.tipo === "like") {
                statsByGenre[key].likes++;
                totalLikes++;
            } else if (v.tipo === "dislike") {
                statsByGenre[key].dislikes++;
                totalDislikes++;
            }

            totalVotes++;
        }

        // 4) Transformar a array y calcular porcentajes
        let genres = Object.values(statsByGenre).map((g) => ({
            name: g.label,
            likes: g.likes,
            dislikes: g.dislikes,
        }));

        // Si no hay likes, usamos votos totales para %; si hay likes, solo likes
        const baseForPercent = totalLikes > 0 ? totalLikes : totalVotes;

        genres = genres
            .map((g) => {
                const weight = totalLikes > 0 ? g.likes : g.likes + g.dislikes;
                const percent = baseForPercent > 0
                    ? Math.round((weight / baseForPercent) * 100)
                    : 0;
                return { ...g, percent };
            })
            .sort((a, b) => b.percent - a.percent);

        const dominantGenre = genres.length > 0 ? genres[0].name : null;

        // 5) Toxicidad = porcentaje de dislikes sobre votos totales
        const toxicity =
            totalVotes > 0 ? Math.round((totalDislikes / totalVotes) * 100) : 0;

        // 6) Mood y tags básicos (lógica simple pero resultona)
        function getMoodLabel(toxicity, dominantGenre) {
            if (!dominantGenre) return "Explorando sonidos";

            if (toxicity >= 70) {
                if (["Trap", "Drill", "Dembow", "Rap"].includes(dominantGenre)) {
                    return "Modo demonio nocturno";
                }
                return "Crítico profesional de Spotify";
            }

            if (toxicity >= 40) {
                return `Selectivo con el ${dominantGenre}`;
            }

            return `Buen rollo con el ${dominantGenre}`;
        }

        function getMoodTags(toxicity, dominantGenre, totalVotes) {
            const tags = [];

            if (dominantGenre) tags.push(`fan del ${dominantGenre.toLowerCase()}`);

            if (toxicity >= 70) {
                tags.push("hater fino", "no compro cualquier tema");
            } else if (toxicity >= 40) {
                tags.push("exigente", "o me flipa o nada");
            } else {
                tags.push("flow chill", "mente abierta");
            }

            if (totalVotes >= 50) tags.push("usuario veterano");
            if (totalVotes < 10) tags.push("recién llegado");

            return tags;
        }

        const moodLabel = getMoodLabel(toxicity, dominantGenre);
        const moodTags = getMoodTags(toxicity, dominantGenre, totalVotes);

        // 7) Badges desbloqueados
        const badges = [];

        if (totalVotes >= 1) {
            badges.push({ icon: "🔥", label: "Primer beef votado" });
        }
        if (totalLikes >= 10) {
            badges.push({ icon: "🎧", label: "10 canciones que te han volado la cabeza" });
        }
        if (totalLikes >= 30 && dominantGenre) {
            badges.push({ icon: "🖤", label: `Fan oficial del ${dominantGenre}` });
        }
        if (totalDislikes >= 10) {
            badges.push({ icon: "💣", label: "Hater elegante (10 no me gusta)" });
        }

        // 8) Respuesta final
        res.json({
            username,
            toxicity,
            totalVotes,
            totalLikes,
            totalDislikes,
            genres,
            dominantGenre,
            moodLabel,
            moodTags,
            badges,
        });
    } catch (err) {
        console.error("Error en GET /api/sound-profile:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
    console.log(`BeefMusic API escuchando en http://localhost:${port}`);
});
