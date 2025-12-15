import {StatusCodes} from "http-status-codes";
import {ResponsableError} from "../custom-error";

class SendOTPFailure extends ResponsableError {
    StatusCode: number = StatusCodes.BAD_REQUEST;
    constructor(public message: string) {
        super(message);
        Object.setPrototypeOf(this, SendOTPFailure.prototype);
    }
    serialize(): {message: string} {
        return {message: this.message};
    }
}

export default SendOTPFailure;
