import jwt from 'jsonwebtoken'
import pool from "../db/db.js";
import { API_KEY_GOOGLE_MAPS, JWT_SECRET } from "../config.js";
import { verifiedRuc } from '../services/ruc.js';

const generateSubPartner = () => {
    const timestamp = Date.now().toString(); // ej: 1728829291812
    return timestamp;
};

export const completeRegisterController = async (req, res) => {

    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ ok: false, message: 'Token no proporcionado', code: 401 });

        const token = authHeader.split(' ')[1];

    try {
        
        // Verificar y decodificar el token
        const decoded = jwt.verify(token, JWT_SECRET);
        const subUser = decoded.sub;

        const { name, category, subcategory } = req.body;

        if (!name || !category || !subcategory) return res.status(403).json({ok: false, message: 'No se han recibido datos'})

            const sqlVerify = `SELECT * FROM users WHERE sub_user = ? AND role_user = ?`
            const [ verifyUser ] = await pool.query(sqlVerify, [ subUser, 'socio' ])

            if (verifyUser.length === 0) return res.status(403).json({ok: false, message: 'No estas autorizado para la acción', error: 'Not Authorization', code: 403})

                const subPartner = generateSubPartner();

                const sqlInsert = `INSERT INTO partners (sub_partner, owner_sub_user, name_partner) VALUES (?, ?, ?)`;
                const [sqlCreate] = await pool.query(sqlInsert, [subPartner, subUser, name]);

                const sqlCatt = 'INSERT INTO partner_categories (sub_partner, type_partner, subtype_category, created_category) VALUES (?, ?, ?, NOW())'
                const [ sqlAdd ] = await pool.query(sqlCatt, [ subPartner, category, subcategory ])

                if (sqlCreate.affectedRows === 0 || sqlAdd.affectedRows === 0) return res.status(500).json({ok: false, message: 'No se pudo crear el socio', error: 'Not Created', code: 500})

                    const payload = {
                        sub_partner: subPartner,
                    }

                    const tokenPartner = jwt.sign(payload, JWT_SECRET, { expiresIn: '1y' })

                    return res.status(200).json({ok: true, message: 'Se creo el socio', partner: tokenPartner, code: 200})

    } catch (error) {
        return res.status(500).json({ok: false, message: error.message, error: error, code: 500})
    }

}

export const verifiedRUCController = async (req, res) => {
    
    if (!req.body) return res.status(403).json({ok: false, message: 'No se enviaron los datos'})

    try {

        const { ruc } = req.body;

        if (!ruc) return res.status(403).json({ok: false, message: 'No se recibio el RUC'})
        
            const response = await verifiedRuc(ruc)

            const { success, data } = response;

            if (!success || data.estado !== 'ACTIVO' || data.condicion !== 'HABIDO') return res.status(403).json({ok: false, message: `No se encontró al RUC`, error: 'RUC invalid', code: 403})

                return res.status(201).json({ok: true, message: 'RUC válido', code: 201, error: ''})

    } catch (error) {
        return res.status(500).json({ok: false, message: `${error.message}`, error: error, code: 500})
    }
}

export const completeInfoController = async (req, res) => {

    const { ruc, direction } = req.body;
    
    if (!ruc || !direction) return res.status(403).json({ok: false, message: `No se recepcionaron los datos`})
    
    try {
        
        const URL_DECODE_LOCATION = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(direction)}&key=${API_KEY_GOOGLE_MAPS}`;

        const response = await fetch(URL_DECODE_LOCATION);
        const data = await response.json()

        if (data.status !== 'OK') return res.status(404).json({ok: false, message: 'Dirección no encontrada', code: 404})
        
        const { lat, lng } = data.results[0].geometry.location;

        const sqlUpdateInfo = `UPDATE partners SET ruc_partner = ?, locationName_partner = ?, location_partner = ? WHERE sub_partner = ?`
        const [ updateInfo ] = await pool.query(sqlUpdateInfo, [ ruc, direction,  ])

        return res.status(200).json({ ok: true, address, lat, lng });

    } catch (error) {
        return res.status(500).json({ok: false, message: `Error al decodigicar: ${error.message}`, error: error, code: 500})
    }
}