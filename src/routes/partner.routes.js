import { Router } from "express";
import { completeRegisterController, completeInfoController, verifiedRUCController } from "../controllers/partner.controllers.js";

const router = Router();

router.post('/register/complete-register', completeRegisterController)
router.post('/register/verified-ruc', verifiedRUCController)
router.post('/register/complete-info', completeInfoController)

export default router;