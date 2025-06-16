import { Router } from 'express';
import { registerController, verifyCodeController } from '../controllers/register.controllers.js';

const router = Router();

router.post('/auth/login', registerController)
router.post('/auth/code', verifyCodeController)

export default router;