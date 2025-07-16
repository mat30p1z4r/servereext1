// server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// --- Clave Secreta para JWT ---
// Leemos la clave secreta desde las variables de entorno de Render.
// Si no existe (ej. en desarrollo local), usamos una por defecto.
const JWT_SECRET = process.env.JWT_SECRET || 'secreto-local-para-pruebas';

// --- Base de Datos Simulada ---
// En una aplicación real, esto vendría de una base de datos como MySQL, PostgreSQL, etc.
// Las contraseñas están "hasheadas". Nunca guardes contraseñas en texto plano.
const users = [
    {
        username: 'usuarioA',
        // Contraseña hasheada para "password123"
        passwordHash: bcrypt.hashSync('password123', 10),
        script: 'scriptA'
    },
    {
        username: 'usuarioB',
        // Contraseña hasheada para "password456"
        passwordHash: bcrypt.hashSync('password456', 10),
        script: 'scriptB'
    }
];

// === ENDPOINT DE LOGIN ===
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    const isPasswordValid = bcrypt.compareSync(password, user.passwordHash);
    if (!isPasswordValid) {
        return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    // Si las credenciales son válidas, creamos un token
    const token = jwt.sign({ username: user.username, script: user.script }, JWT_SECRET, { expiresIn: '8h' });

    console.log(`Usuario '${username}' ha iniciado sesión.`);
    res.json({ token });
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