export const indexController = (req, res) => {
    return res.status(201).json({ok: true, message: 'Bienvenido a la API de Ándale'})
}