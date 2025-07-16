// server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const CryptoJS = require('crypto-js'); // Nueva dependencia

const app = express();
app.use(cors());
app.use(express.json());

// --- Claves Secretas ---
const JWT_SECRET = process.env.JWT_SECRET || 'secreto-local-para-pruebas';
// Nueva clave para encriptar/desencriptar contraseñas de autologin
const ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET || 'otra-clave-secreta-para-encriptacion';

// Función para encriptar
function encrypt(text) {
    return CryptoJS.AES.encrypt(text, ENCRYPTION_SECRET).toString();
}

// Función para desencriptar
function decrypt(ciphertext) {
    const bytes = CryptoJS.AES.decrypt(ciphertext, ENCRYPTION_SECRET);
    return bytes.toString(CryptoJS.enc.Utf8);
}

// --- Base de Datos Simulada ---
// Las contraseñas para autologin ahora están encriptadas
const users = [
    {
        id: '101',
        username: 'usuarioA',
        // Contraseña en texto plano: 'password123'
        encryptedPassword: encrypt('password123'), // Contraseña encriptada
        passwordHash: bcrypt.hashSync('password123', 10),
        script: 'scriptA'
    },
    {
        id: '102',
        username: 'usuarioB',
        // Contraseña en texto plano: 'password456'
        encryptedPassword: encrypt('password456'), // Contraseña encriptada
        passwordHash: bcrypt.hashSync('password456', 10),
        script: 'scriptB'
    }
];

// === ENDPOINT DE LOGIN ===
app.post('/login', (req, res) => {
    const { id } = req.body; // Ahora esperamos un 'id'

    const user = users.find(u => u.id === id);
    if (!user) {
        return res.status(401).json({ message: 'ID de usuario incorrecto' });
    }

    // Desencriptamos la contraseña para enviarla a la extensión
    const decryptedPassword = decrypt(user.encryptedPassword);

    // Si el ID es válido, creamos un token
    const token = jwt.sign({ username: user.username, script: user.script }, JWT_SECRET, { expiresIn: '8h' });

    console.log(`ID '${id}' ha iniciado sesión como usuario '${user.username}'.`);
    // Devolvemos el token y la contraseña desencriptada para el autologin
    res.json({ token, username: user.username, password: decryptedPassword });
});

// === MIDDLEWARE DE AUTENTICACIÓN ===
// Esta función protege los endpoints. Se ejecuta antes de la lógica principal.
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"

    if (token == null) {
        return res.sendStatus(401); // No hay token
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Token inválido o expirado
        }
        req.user = user; // Guardamos la info del usuario del token en la request
        next(); // Pasamos al siguiente paso (la lógica del endpoint)
    });
}

// === ENDPOINT PARA REGISTRAR TIEMPO (PROTEGIDO) ===
app.post('/log_session', authenticateToken, (req, res) => {
    // Gracias al middleware, aquí solo llegamos si el token es válido.
    // El usuario que hace la petición está en req.user
    const loggedInData = req.body;
    const userFromToken = req.user;

    console.log(`Datos de sesión recibidos del usuario '${userFromToken.username}':`, loggedInData);
    console.log(`Este usuario usa el script: '${userFromToken.script}'`);

    // Aquí iría tu lógica para guardar 'loggedInData' en tu base de datos real,
    // asociándolo con el 'userFromToken.username'.

    res.status(200).json({ status: 'success', message: 'Datos recibidos' });
});

// Render usa la variable de entorno PORT. Si no existe, usamos 3000.
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor de autenticación corriendo en el puerto ${PORT}`);
});