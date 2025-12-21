import express from "express";
import userController from "@/controllers/user-controller";
import {authMiddleware} from "@/middleware/auth-middleware";
import {expressSchemaValidator} from "@/middleware/schema-validator";

const router = express.Router();

router.post(
    "/signup",
    authMiddleware.isAuthorizedOTP,
    authMiddleware.isOTPTypeisRegister,
    expressSchemaValidator("/students/signup"),
    userController.signupAsStudent
);
router.post(
    "/login",
    expressSchemaValidator("/students/login"),
    userController.loginAsStudent
);
router.get("/logout", userController.logoutAsStudent);
router.get(
    "/refresh",
    userController.checkStudentLockStatus,
    userController.refreshStudentToken
);
router.delete(
    "/:id",
    authMiddleware.isAuthorized,
    userController.checkStudentLockStatus,
    userController.deleteStudent
);
router.get(
    "/:id",
    authMiddleware.isAuthorized,
    userController.checkStudentLockStatus,
    userController.getStudent
);
router.get(
    "/",
    authMiddleware.isAuthorized,
    authMiddleware.isAdmin,
    userController.getStudents
);
router.put(
    "/:id",
    authMiddleware.isAuthorized,
    expressSchemaValidator("/students/:id"),
    userController.checkStudentLockStatus,
    userController.updateStudentInfo
);
router.post(
    "/resetPassword",
    authMiddleware.isAuthorized,
    authMiddleware.isAuthorizedOTP,
    authMiddleware.isOTPTypeisResetPw,
    expressSchemaValidator("/students/resetPassword"),
    userController.checkStudentLockStatus,
    userController.updateStudentPw
);
router.post(
    "/updateLockStatus",
    authMiddleware.isAuthorized,
    expressSchemaValidator("/students/updateLockStatus"),
    userController.checkStudentLockStatus,
    userController.lockStudentAccount
);
router.post(
    "/checkLockStatus",
    authMiddleware.isAuthorized,
    userController.getStudentLockStatus
);

export default router;
