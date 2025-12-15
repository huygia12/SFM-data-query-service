import express from "express";
import categoryController from "@/controllers/category-controller";
import userController from "@/controllers/user-controller";
import {authMiddleware} from "@/middleware/auth-middleware";

const router = express.Router();

router.get(
    "/",
    authMiddleware.isAuthorized,
    userController.checkStudentLockStatus,
    categoryController.getCategories
);

export default router;
