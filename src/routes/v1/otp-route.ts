import express from "express";
import otpController from "@/controllers/otp-controller";
import userController from "@/controllers/user-controller";
import {expressSchemaValidator} from "@/middleware/schema-validator";
import {authMiddleware} from "@/middleware/auth-middleware";

const router = express.Router();

router.post(
    "/create",
    authMiddleware.isAuthorizedToAccessOTPAPI,
    expressSchemaValidator("/otps/create"),
    userController.checkStudentLockStatus,
    otpController.generateAndSendOTP
);

router.post(
    "/check",
    authMiddleware.isAuthorizedToAccessOTPAPI,
    expressSchemaValidator("/otps/check"),
    userController.checkStudentLockStatus,
    otpController.checkOTP
);

export default router;
