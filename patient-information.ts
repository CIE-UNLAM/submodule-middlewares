import {NextFunction, Request, Response} from "express";
import {Role} from "../utils/session";
import {CustomError} from "../utils/http-response";
import httpStatus from "http-status-codes";
import Context from "./session";

export function onlyViewMyInformation(req: Request, res: Response, next: NextFunction) {
    const sess = Context.get(req).session;
    if (sess.role.some(e => e == Role.PG) && req.params.username !== sess.username) {
        new CustomError(httpStatus.FORBIDDEN, 'Lo siento, sólo puedes ver tu información').send(res);
        return;
    }
    next();
}