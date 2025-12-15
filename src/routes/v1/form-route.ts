import express from "express";
import formController from "@/controllers/form-controller";
import userController from "@/controllers/user-controller";
import {authMiddleware} from "@/middleware/auth-middleware";
import {expressSchemaValidator} from "@/middleware/schema-validator";

const router = express.Router();
// common
router.use(authMiddleware.isAuthorized, userController.checkStudentLockStatus);

// each api
router.get("/:id", formController.getForm);
router.get("/statistic/count", formController.getNumberOfForms);
router.post(
    "/statistic/group-by-category",
    expressSchemaValidator("/forms/statistic/group-by-category"),
    formController.getEachCategoryNumberOfForms
);
router.post(
    "/createForm",
    expressSchemaValidator("/forms/createForm"),
    formController.createForm
);
router.post(
    "/uploadForm",
    expressSchemaValidator("/forms/uploadForm"),
    formController.uploadForm
);
router.post(
    "/:id",
    expressSchemaValidator("/forms/createForm"),
    formController.updateForm
);
router.delete("/:id", formController.deleteForm);
router.post("/", expressSchemaValidator("/forms"), formController.getForms);
router.patch(
    "/:id",
    authMiddleware.isAdmin,
    expressSchemaValidator("/forms/:id"),
    formController.updateFormStatus
);

export default router;
