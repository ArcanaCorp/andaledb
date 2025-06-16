import { Router } from "express";
import { accountController, completedController, loginController, verifyController } from "../controllers/auth.controllers.js";

const router = Router();

router.post('/login', loginController)
router.post('/verify', verifyController)
router.post('/completed', completedController)
router.post('/account', accountController)

export default router