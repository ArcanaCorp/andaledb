import express from 'express';
import http from 'http';
import cors from 'cors';
import { Server } from "socket.io";

import { PORT } from './config.js';

const app = express();
const server = http.createServer(app);

//Configurar socket.io
export const io = new Server(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
    }
})

//Middlewares de Express
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

//RUTAS USER
import indexRoutes from "./routes/index.routes.js";
import authRoutes from "./routes/auth.routes.js";

//USE ROUTERS USER
app.use('/api/v1/', indexRoutes)
app.use('/api/v1/auth', authRoutes)

//RUTAS SOCIO
import authSocioRoutes from './routes/register.routes.js'
import completeInfoSocioRoutes from './routes/partner.routes.js'

//USE ROUTERS SOCIO
app.use('/api/v1/socio', authSocioRoutes)
app.use('/api/v1/socio', completeInfoSocioRoutes)

// Manejo de errores
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});

// -------------- SOCKET.IO -------------------
io.on('connection', (socket) => {
    console.log('Usuario conectado', socket.id);

    //Escuchar registro del usuario
    socket.on('register', ({ userId, role }) => {
        const roomName = `${role}-${userId}`;
        socket.join(roomName);
        console.log(`El usuario ${userId} registrado en la sala ${roomName}`);
    });

    socket.on('disconnect', () => {
        console.log(`Usuario desconectado ${socket.id}`);
    })
});

server.listen(PORT, () => {
    console.log(`Listening on port http://localhost:${PORT}`);
});