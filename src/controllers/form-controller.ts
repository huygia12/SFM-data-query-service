import {Request, Response} from "express";
import formService from "@/services/form-service";
import {StatusCodes} from "http-status-codes";
import {ResponseMessage} from "@/common/constants";
import {FormsRetrievement, FormStatusUpdate} from "@/common/schemas";
import {FormStatus} from "@prisma/client";
import jwtService from "@/services/jwt-service";
import {UserInToken, UserRole} from "@/common/types";
import userService from "@/services/user-service";
import UserNotFoundError from "@/errors/user/user-not-found";
import FormNotFoundError from "@/errors/form/form-not-found";

const transformToEntries = (data: Record<string, string>) => {
    return Object.entries(data).map(([key, value]) => ({
        name: key,
        value: value,
    }));
};

const createForm = async (req: Request, res: Response) => {
    const studentId = req.query.studentId as string;
    const categoryId = req.query.categoryId as string;
    const reqBody = req.body;

    const entries = transformToEntries(reqBody);

    const pk = await userService.getStudentPK(studentId);

    if (!pk) {
        throw new Error("Cannot get PK");
    }

    const formId = await formService.insertForm(
        JSON.stringify(entries),
        studentId,
        categoryId,
        pk
    );

    return res.status(StatusCodes.CREATED).json({
        message: ResponseMessage.SUCCESS,
        info: {
            formId: formId,
        },
    });
};

const updateForm = async (req: Request, res: Response) => {
    const formId = req.params.id as string;
    const reqBody = req.body;

    const form = await formService.getFormFullJoin(formId);
    if (!form) {
        throw new FormNotFoundError(
            "Form with id " + formId + " cannot be found"
        );
    }

    const pk = await userService.getStudentPK(form.studentId);
    if (!pk) {
        throw new Error("Cannot get PK");
    }

    const entries = transformToEntries(reqBody);
    await formService.updateForm(formId, JSON.stringify(entries), pk);

    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
    });
};

const deleteForm = async (req: Request, res: Response) => {
    const formId = req.params.id as string;

    await formService.deleteForm(formId);

    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
    });
};

const uploadForm = async (req: Request, res: Response) => {
    const adminId = req.query.adminId as string;
    const categoryId = req.body.categoryId as string;
    const status = req.body.status as FormStatus;
    const fields = req.body.fields;
    const studentCode = req.body.fields.STUDENT_ID as string;

    const student = await userService.getStudentDTOByStudentCode(studentCode);
    if (!student)
        throw new UserNotFoundError(
            "Student with code " + studentCode + " cannot be found"
        );

    const pk = await userService.getStudentPK(student.studentId);
    if (!pk) {
        throw new Error("Cannot get PK");
    }

    const entries = transformToEntries(fields);

    const formId = await formService.insertForm(
        JSON.stringify(entries),
        student.studentId,
        categoryId,
        pk,
        status,
        adminId
    );

    return res.status(StatusCodes.CREATED).json({
        message: ResponseMessage.SUCCESS,
        info: {
            formId: formId,
        },
    });
};

const getForm = async (req: Request, res: Response) => {
    const formId = req.params.id as string;

    const form = await formService.getFormFullJoin(formId);

    if (!form)
        throw new FormNotFoundError(
            "Form with id " + formId + " cannot be found"
        );
    const pk = await userService.getStudentPK(form.studentId);

    if (!pk) {
        throw new Error("Cannot get PK");
    }
    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: formService.convertToFormFullJoin(form, pk),
    });
};

const getForms = async (req: Request, res: Response) => {
    const studentId = req.query.studentId as string;
    const reqBody = req.body as FormsRetrievement;
    const fromDate =
        typeof req.body.fromDate == "string"
            ? parseDate(req.body.fromDate)
            : undefined;
    const toDate =
        typeof req.body.toDate == "string"
            ? parseDate(req.body.toDate)
            : undefined;
    let categoryIds = req.body.categoryIds as string[] | undefined;
    let status = reqBody.status as FormStatus[] | undefined;

    categoryIds = categoryIds?.length == 0 ? undefined : categoryIds;
    status = status?.length == 0 ? undefined : status;

    const forms = await formService.getFormFullJoins({
        keySearch: req.body.keySearch,
        categoryIds: categoryIds,
        status: status,
        fromDate: fromDate,
        toDate: toDate,
        limit: reqBody.limit ?? 20,
        currentPage: reqBody.currentPage ?? 1,
        studentId: studentId,
    });

    const pkObjects = await userService.getStudentsPK(
        forms.map((form) => form.studentId)
    );

    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: forms.map((form) => {
            const pk = pkObjects.find(
                (object) => object.studentId == form.studentId
            );
            return formService.convertToFormFullJoin(form, pk?.privateKey!);
        }),
    });
};

const updateFormStatus = async (req: Request, res: Response) => {
    const accessToken: string | string[] | undefined =
        req.headers["authorization"];
    const {userId} = jwtService.decodeToken(
        accessToken!.replace("Bearer ", "")
    ) as UserInToken;

    const formId = req.params.id as string;
    const reqBody = req.body as FormStatusUpdate;

    const form = await formService.updateFormStatus(
        formId,
        userId,
        reqBody.status
    );

    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: form,
    });
};

const getEachCategoryNumberOfForms = async (req: Request, res: Response) => {
    const accessToken: string | string[] | undefined =
        req.headers["authorization"];
    const {role, userId} = jwtService.decodeToken(
        accessToken!.replace("Bearer ", "")
    ) as UserInToken;
    const fromDate =
        typeof req.body.fromDate == "string"
            ? parseDate(req.body.fromDate)
            : undefined;
    const toDate =
        typeof req.body.toDate == "string"
            ? parseDate(req.body.toDate)
            : undefined;
    const data = await formService.getFormNumberOfEachCategories({
        studentId: UserRole.STUDENT === role ? userId : undefined,
        fromDate: fromDate,
        toDate: toDate,
    });

    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: data,
    });
};

const getNumberOfForms = async (req: Request, res: Response) => {
    const accessToken: string | string[] | undefined =
        req.headers["authorization"];
    const {role, userId} = jwtService.decodeToken(
        accessToken!.replace("Bearer ", "")
    ) as UserInToken;

    const data = await formService.getNumberOfForms({
        userId: UserRole.ADMIN === role ? undefined : userId,
    });

    return res.status(StatusCodes.OK).json({
        message: ResponseMessage.SUCCESS,
        info: {
            totalForms: data,
        },
    });
};

const parseDate = (dateString: string): Date | undefined => {
    const dateRegex = /^(\d{2})\/(\d{2})\/(\d{4})$/;
    const match = dateString.match(dateRegex);

    if (!match) {
        console.log("go in here");
        return undefined;
    }

    const [, day, month, year] = match;
    return new Date(parseInt(year), parseInt(month) - 1, parseInt(day));
};

export default {
    createForm,
    getForms,
    getForm,
    uploadForm,
    updateForm,
    deleteForm,
    updateFormStatus,
    getEachCategoryNumberOfForms,
    getNumberOfForms,
};
