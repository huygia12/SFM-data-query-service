import express from "express";
import userController from "@/controllers/user-controller";
import {expressSchemaValidator} from "@/middleware/schema-validator";
import {authMiddleware} from "@/middleware/auth-middleware";

const router = express.Router();

router.post(
    "/signup",
    expressSchemaValidator("/admins/signup"),
    userController.signupAsAdmin
);
router.post(
    "/login",
    expressSchemaValidator("/admins/login"),
    userController.loginAsAdmin
);
router.get("/logout", userController.logoutAsAdmin);
router.post("/refresh", userController.refreshAdminToken);
router.delete(
    "/:id",
    authMiddleware.isAuthorized,
    authMiddleware.isAdmin,
    userController.deleteAdmin
);
router.get(
    "/:id",
    authMiddleware.isAuthorized,
    authMiddleware.isAdmin,
    userController.getAdmin
);
router.put(
    "/:id",
    authMiddleware.isAuthorized,
    expressSchemaValidator("/admins/:id"),
    userController.updateAdminInfo
);

export default router;
