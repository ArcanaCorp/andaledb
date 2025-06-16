import { API_FACTILIZA_RUC } from "../config.js"

export const verifiedRuc = async (ruc) => {
    try {
        
        const response = await fetch(`https://api.factiliza.com/v1/ruc/info/${ruc}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${API_FACTILIZA_RUC}`
            }
        })

        if (!response.ok) {
            const errorBody = await response.text(); // Intenta obtener cuerpo de error en texto
            throw new Error(`ERROR ENDPOINT FACTILIZA: ${response.statusText} | ${errorBody}`);
        }
        
        const data = await response.json();

        return data;

    } catch (error) {
        return { ok: false, message: `Error: ${error.message}`, error: error, code: 500 }
    }
}