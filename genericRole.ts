import {NextFunction, Request, Response} from "express";
import httpStatus from "http-status-codes";
import Context from "./session";
import {CustomError} from '../utils/http-response'
import {Role} from "../utils/session";

export function getVerifiedRoleFunc(roles: number[]) {
    roles.push(Role.ROOT);
    return (req: Request, res: Response, next: NextFunction) => {
        try {
            const session = Context.get(req).session;
            if (!session.role.some(e => roles.includes(e))) {
                new CustomError(httpStatus.UNAUTHORIZED, `you don't have permissions for ${req.url}`).send(res);
                return;
            }
            next();
        } catch (err) {
            new CustomError(httpStatus.UNAUTHORIZED, 'invalid token').send(res);
            return;
        }
    }
}