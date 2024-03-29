import {NextFunction, Request, Response} from "express";
import {Session, SessionManager} from "../utils/session";
import httpStatus from "http-status-codes";
import http from "http";
import qs from 'query-string'
import {CustomError, sendHTTPError} from "../utils/http-response";
import axios from "axios";

export async function session(req: Request, res: Response, next: NextFunction) {
    let token: string;
    const tokenStartingPosition = 7;
    const authHeader: string = <string>req.headers.authorization;
    try {
        if (authHeader && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(tokenStartingPosition, authHeader.length);
        } else {
            token = <string>req.query.access_token;
        }
        const sess = await SessionManager.getSession(token);
        if (sess == null) {
            new CustomError(httpStatus.UNAUTHORIZED, 'Lo siento. Necesita iniciar sesión').send(res);
            return;
        }
        Context.set(req, sess);
        next();
    } catch (err) {
        sendHTTPError(res, err);
    }
}

export async function sessionHTTP(req: Request, res: Response, next: NextFunction) {
    let token : string;
    const tokenStartingPosition = 7;
    const authHeader: string = <string>req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")){
        token = authHeader.substring(tokenStartingPosition, authHeader.length);
    } else {
        token = <string>req.query.access_token;
    }
    try {
        const url = `${process.env.USERS_SERVICE}auth/token/info?access_token=${token}`;
        const {data, status} = await axios.get<Session>(url);
        Context.set(req, data);
        next();
    } catch(err) {
        if (axios.isAxiosError(err) && err.response) {
            let local = <CustomError> err.response.data;
            err = new CustomError(local.status, local.message);
        }
        sendHTTPError(res, err);
    }
}

export async function authenticateWS(req: http.IncomingMessage): Promise<Session> {
    let url = req.url;
    if (!url) {
        throw new CustomError(httpStatus.INTERNAL_SERVER_ERROR, 'Error interno del servidor web socket');
    }
    let params = <{ access_token: string }>qs.parse(url.split('?')[1]);
    const at = params.access_token;
    let sess = await SessionManager.getSession(at);
    if (sess == null) {
        throw new CustomError(httpStatus.UNAUTHORIZED, 'Lo siento. Necesita iniciar sesión');
    }
    return sess;
}

export async function authenticateWSHTTP(req: http.IncomingMessage): Promise<Session> {
    let url = req.url;
    if (!url) {
        throw new CustomError(httpStatus.INTERNAL_SERVER_ERROR, 'Error interno del servidor web socket');
    }
    let params =  <{access_token: string}>qs.parse(url.split('?')[1]);
    const at = params.access_token;
    let urlHTTP = `${process.env.USERS_SERVICE}auth/token/info?access_token=${at}`;
    const {data, status} = await axios.get<Session>(urlHTTP);
    if (data == null || status !== httpStatus.OK) {
        throw new CustomError(httpStatus.UNAUTHORIZED, 'Lo siento. Necesita iniciar sesión');
    }
    return data;
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
            throw new CustomError(httpStatus.INTERNAL_SERVER_ERROR, 'Lo siento, no se puede obtener contexto de la solicitud');
        }
        return ret;
    }
}