import jwt from 'jsonwebtoken'
import pool from "../db/db.js";
import { JWT_SECRET } from "../config.js";
import { serviceSendOTP } from '../services/otp.js';

const generateCodeOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const generateSubUser = (phone) => {
    const phoneStr = String(phone);
    if (!/^\d{9}$/.test(phoneStr)) {
        throw new Error("Número de teléfono inválido (debe tener 9 dígitos)");
    }
    const shuffled = phoneStr.split('').sort(() => Math.random() - 0.5).join('');
    const extraDigits = Math.floor(10 + Math.random() * 90);
    return shuffled + extraDigits;
};

const insertOTP = async (sub, code) => {
    const expires = new Date(Date.now() + 10 * 60 * 1000);
    const query = `INSERT INTO login_tokens (sub_user, code_token, created_token, expires_token, used_token) VALUES (?, ?, NOW(), ?, 0)`;
    const [result] = await pool.query(query, [sub, code, expires]);
    return result.affectedRows > 0;
};

export const registerController = async (req, res) => {

    if (!req.body) return res.status(400).send('Missing body')

        const { phone } = req.body

        if (!phone || !/^\d{9}$/.test(phone)) return res.status(400).send('Missing phone')

            try {
                
                let user;

                const [existingUsers] = await pool.query('SELECT * FROM users WHERE phone_user = ?', [phone]);

                // Generar OTP
                const code = generateCodeOTP();

                if (existingUsers.length === 0) {

                    const subUser = generateSubUser(phone);
                    const insertUserQuery = `INSERT INTO users (sub_user, phone_user, name_user, avatar_user, role_user, created_user) VALUES (?, ?, '', '', 'socio', NOW())`;
                    const [userResult] = await pool.query(insertUserQuery, [subUser, phone]);

                    if (userResult.affectedRows === 0) return res.status(500).json({ ok: false, message: 'Error al registrar usuario', code: 500 });

                    // Consultar usuario recién creado
                    const [newUserRows] = await pool.query(
                        'SELECT id_user, sub_user, role_user FROM users WHERE phone_user = ?',
                        [phone]
                    );

                    user = newUserRows[0];
                
                } else {
                    user = existingUsers[0];
                }
                
                const codeInserted = await insertOTP(user.sub_user, code);

                if (!codeInserted) return res.status(500).json({ ok: false, message: 'Error al generar OTP', code: 500 });

                    if (process.env.NODE_ENV !== 'production') {
                        console.log(`Código enviado a ${phone}: ${code}`);
                    }

                    // Enviar OTP al teléfono
                    const sendOTP = await serviceSendOTP(phone, code);

                    if (!sendOTP.ok) return res.status(500).json({ ok: false, message: 'Error al enviar el OTP', code: 500 });

                        // Generar JWT con sub_user y role_user
                        const payload = {
                            id: user.id_user,
                            sub: user.sub_user,
                            role: user.role_user
                        }

                        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

                        return res.status(200).json({ok: true, message: 'Se envió el código de verificación', token: token, code: 200});

            } catch (error) {
                return { ok: false, message: `Error en el servidor: ${error.message}`, error: error, code: 500 }
            }

}

export const verifyCodeController = async (req, res) => {
    
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ ok: false, message: 'Token no proporcionado', code: 401 });

        const token = authHeader.split(' ')[1];

        try {
            
            // Verificar y decodificar el token
            const decoded = jwt.verify(token, JWT_SECRET);
            const subUser = decoded.sub;

            if (!subUser) return res.status(401).json({ ok: false, message: 'Token inválido: falta sub_user', code: 401 });

                const { code } = req.body;

                if (!code || !/^\d{6}$/.test(code)) return res.status(400).json({ ok: false, message: 'Código OTP inválido', code: 400 });

                    // Obtener el teléfono usando el sub_user
                    const [userRows] = await pool.query(`SELECT * FROM users WHERE sub_user = ?`, [subUser]);

                    if (userRows.length === 0) return res.status(404).json({ ok: false, message: 'Usuario no encontrado', code: 404 });

                    const user = userRows[0];

                    // Buscar OTP válido
                    const searchToken = 'SELECT * FROM login_tokens WHERE sub_user = ? AND code_token = ? AND used_token = 0 AND expires_token > NOW() ORDER BY created_token DESC LIMIT 1'
                    const [tokens] = await pool.query(searchToken, [user.sub_user, code]);

                    if (tokens.length === 0) return res.status(401).json({ ok: false, message: 'Código inválido o expirado', code: 401 });

                        // Marcar como usado
                        await pool.query(`UPDATE login_tokens SET used_token = 1 WHERE id_token = ?`, [tokens[0].id_token]);

                        const completed = user.name_user === '' ? false : true;

                        // Retornar éxito con datos del usuario
                        return res.status(200).json({ok: true, message: 'Código verificado correctamente', code: 200, completed: completed});

        } catch (error) {
            return res.status(401).json({ok: false, message: 'Token inválido o expirado', error: error.message, code: 401});
        }
    
}