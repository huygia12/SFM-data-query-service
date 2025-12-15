import {StatusCodes} from "http-status-codes";
import {ResponsableError} from "../custom-error";

class RequestToLockedAccount extends ResponsableError {
    StatusCode: number = StatusCodes.LOCKED;
    constructor(public message: string) {
        super(message);
        Object.setPrototypeOf(this, RequestToLockedAccount.prototype);
    }
    serialize(): {message: string} {
        return {message: this.message};
    }
}

export default RequestToLockedAccount;
