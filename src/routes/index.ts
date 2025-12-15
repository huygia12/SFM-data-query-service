import express, {Request, Response} from "express";
import studentRoute from "@/routes/v1/student-route";
import adminRoute from "@/routes/v1/admin-route";
import formRoute from "@/routes/v1/form-route";
import otpRoute from "@/routes/v1/otp-route";
import categoryRoute from "@/routes/v1/category-route";
import {NextFunction} from "express-serve-static-core";

const router = express.Router();
const space = (req: Request, res: Response, next: NextFunction) => {
    console.log("\n");
    next();
};

router.use("/v1/students", space, studentRoute);
router.use("/v1/admins", space, adminRoute);
router.use("/v1/categories", space, categoryRoute);
router.use("/v1/forms", space, formRoute);
router.use("/v1/otps", space, otpRoute);
router.get("/healthcheck", (req: Request, res: Response) =>
    res.sendStatus(200)
);
export const API_v1 = router;
