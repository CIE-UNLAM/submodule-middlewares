import {NextFunction, Request, Response} from "express";
import {Session, SessionManager} from "../utils/session";
import httpStatus from "http-status-codes";
import http from "http";
import qs from 'query-string'
import {CustomError, sendHTTPError} from "../utils/http-response";

export function session(req: Request, res: Response, next: NextFunction) {
    try {
        const at: string = <string>req.query.access_token;
        const sess = SessionManager.getSession(at);
        if (sess == null) {
            new CustomError(httpStatus.UNAUTHORIZED, 'invalid token').send(res);
            return;
        }
        Context.set(req, sess);
        next();
    } catch (err) {
        sendHTTPError(res, err);
    }
}

export function authenticateWS(req: http.IncomingMessage): Session {
    let url = req.url;
    if (!url) {
        throw new CustomError(httpStatus.INTERNAL_SERVER_ERROR, 'internal web socket server error');
    }
    let params =  <{access_token: string}>qs.parse(url.split('?')[1]);
    const at = params.access_token;
    let sess = SessionManager.getSession(at);
    if (sess == null) {
        throw new CustomError(httpStatus.UNAUTHORIZED, 'invalid access token');
    }
    return sess;
}

export default class Context {
    private static bindings = new WeakMap<Request, Context>();
    public session: Session;
    constructor (session: Session) {
        this.session = session;
    }

    static set(req: Request, session: Session) {
        const ctx = new Context(session);
        Context.bind(req, ctx);
    }

    static bind(req: Request, ctx: Context): void {
        Context.bindings.set(req, ctx);
    }

    static get(req: Request) : Context {
        let ret = Context.bindings.get(req);
        if (ret == null) {
            throw new CustomError(httpStatus.INTERNAL_SERVER_ERROR, 'cannot get context for that request');
        }
        return ret;
    }
}