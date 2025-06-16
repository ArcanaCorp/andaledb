import mysql from 'mysql2/promise';
import { HOST_DB, USER_DB, PASSWORD_DB, DATABASE_DB } from "../config.js";

const pool = mysql.createPool({
    host: HOST_DB,
    user: USER_DB,
    password: PASSWORD_DB,
    database: DATABASE_DB,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

export default pool;