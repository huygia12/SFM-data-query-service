import aesHelper from "@/common/aes-util";
import {FormFullJoinBeforeEncrypt} from "@/common/types";
import prisma from "@/common/prisma-client";
import {FormStatus, PersonalForm} from "@prisma/client";
import FormNotFoundError from "@/errors/form/form-not-found";
import FormActionDenied from "@/errors/form/form-action-denied";

const insertForm = async (
    fields: string,
    studentId: string,
    categoryId: string,
    pk: string,
    status: FormStatus = FormStatus.STAGING,
    adminId?: string
): Promise<string | undefined> => {
    const {ciphertext, iv} = aesHelper.encrypt(fields, pk);

    let {personalFormId} = await prisma.personalForm.create({
        data: {
            studentId: studentId,
            categoryId: categoryId,
            status: status,
            data: `${ciphertext}.${iv}`,
            updatedBy: adminId,
        },
        select: {
            personalFormId: true,
        },
    });

    return personalFormId;
};

const parseEntries = (text: string) => {
    return JSON.parse(text) as Array<{name: string; value: string}>;
};

const getFormFullJoin = async (
    formId: string
): Promise<FormFullJoinBeforeEncrypt | null> => {
    const form = await prisma.personalForm.findFirst({
        where: {
            personalFormId: formId,
        },
        include: {
            student: {
                select: {
                    studentId: true,
                    studentCode: true,
                    username: true,
                },
            },
            category: true,
        },
    });

    return form;
};

const convertToFormFullJoin = (
    form: FormFullJoinBeforeEncrypt,
    aesKey: string
) => {
    const [data, iv] = form.data.split(".");

    return {
        ...form,
        fields: parseEntries(aesHelper.decrypt(data, aesKey, iv)),
    };
};

const getFormFullJoins = async (params: {
    categoryIds?: string[];
    studentId?: string;
    keySearch?: string;
    fromDate?: Date;
    toDate?: Date;
    status?: FormStatus[];
    limit: number;
    currentPage: number;
}): Promise<FormFullJoinBeforeEncrypt[]> => {
    const startOfDate =
        params.fromDate && new Date(params.fromDate.setHours(0, 0, 0, 0));
    const endOfDate =
        params.toDate && new Date(params.toDate.setHours(23, 59, 59, 999));

    const forms = await prisma.personalForm.findMany({
        where: {
            studentId: params.studentId,
            categoryId: {
                in: params.categoryIds,
            },
            status: {
                in: params.status,
            },
            createdAt: {
                gte: startOfDate,
                lte: endOfDate,
            },
            student: {
                username: {
                    contains: params.keySearch,
                    mode: "insensitive",
                },
            },
        },
        include: {
            student: {
                select: {
                    studentId: true,
                    studentCode: true,
                    username: true,
                },
            },
            category: true,
        },
        orderBy: {
            createdAt: "desc",
        },
        take: params.limit == 0 ? undefined : params.limit,
        skip: (params.currentPage - 1) * params.limit,
    });
    return forms;
};

const updateFormStatus = async (
    formId: string,
    adminId: string,
    status: FormStatus
): Promise<PersonalForm> => {
    const form = await prisma.personalForm.update({
        where: {
            personalFormId: formId,
        },
        data: {
            status: status,
            updatedBy: adminId,
        },
    });

    return form;
};

const getForm = async (formId: string): Promise<PersonalForm | null> => {
    const form = await prisma.personalForm.findFirst({
        where: {
            personalFormId: formId,
        },
    });

    return form;
};

const updateForm = async (
    formId: string,
    fields: string,
    pk: string
): Promise<void> => {
    const form = await getForm(formId);
    if (!form) {
        throw new FormNotFoundError(
            "Form with id " + formId + " cannot be found"
        );
    }

    if (form.status !== FormStatus.STAGING) {
        throw new FormActionDenied("unable to update this form");
    }

    const {ciphertext, iv} = aesHelper.encrypt(fields, pk);

    await prisma.personalForm.update({
        where: {
            personalFormId: formId,
        },
        data: {
            data: `${ciphertext}.${iv}`,
        },
    });
};

const deleteForm = async (formId: string) => {
    const form = await getForm(formId);
    if (!form) {
        throw new FormNotFoundError(
            "Form with id " + formId + " cannot be found"
        );
    }

    if (form.status === FormStatus.APPROVED) {
        throw new FormActionDenied("unable to delete this form");
    }

    await prisma.personalForm.delete({
        where: {
            personalFormId: formId,
        },
    });
};

const getFormNumberOfEachCategories = async (params: {
    studentId?: string;
    fromDate?: Date;
    toDate?: Date;
}): Promise<{categoryId: string; totalForms: number}[]> => {
    const startOfDate =
        params.fromDate && new Date(params.fromDate.setHours(0, 0, 0, 0));
    const endOfDate =
        params.toDate && new Date(params.toDate.setHours(23, 59, 59, 999));

    const results = await prisma.personalForm.groupBy({
        by: "categoryId",
        where: {
            studentId: params.studentId,
            createdAt: {
                gte: startOfDate,
                lte: endOfDate,
            },
        },
        _count: true,
    });

    const formattedResults = results.map((result) => ({
        categoryId: result.categoryId,
        totalForms: result._count,
    }));

    return formattedResults;
};

const getNumberOfForms = async (params: {userId?: string}): Promise<number> => {
    const numberOfForms = await prisma.personalForm.count({
        where: {
            studentId: params.userId,
        },
    });

    return numberOfForms;
};

export default {
    insertForm,
    updateForm,
    getFormFullJoins,
    getFormFullJoin,
    updateFormStatus,
    deleteForm,
    getFormNumberOfEachCategories,
    getNumberOfForms,
    convertToFormFullJoin,
};
