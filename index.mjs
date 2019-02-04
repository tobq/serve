import http from "http";
import url from "url";
import path from "path";
import mime from "mime";
import fs from "fs";
import request from "request";
import Busboy from "busboy";
import crypto from "crypto";
import pg from "pg";

function captcha(req, res, next) {
    if ("g-recaptcha-response" in req.body) {
        request("https://google.com/recaptcha/api/siteverify?secret=6LfI2QgUAAAAAKDhGdSleU2rEjHLC7WsPvsoSej5&response=" +
            req.body["g-recaptcha-response"], function (err, response, body) {
            if (err) this.res500(req, res, err);
            else if (response.statusCode !== 200) res.writeHead(412);
            else {
                try {
                    body = JSON.parse(body);
                    if (body.success) return next();
                } catch (err) {
                    res.writeHead(500);
                }
            }
            res.end();
        });
    } else {
        res.writeHead(422);
        res.end();
    }
};

function SQLPool(req, res, next) {
    pool.connect(function (err, con) {
        if (err) return this.res500(req, res, err);
        req.sql = con;
        next();
    })
}

function resRedirect(res, url) {
    res.writeHead(302, {
        "Location": url || "/"
    });
    res.end();
}

function JSONBody(req, res, next) {
    try {
        req.body = JSON.parse(req.body.toString("utf8"));
        next();
    } catch (e) {
        res.writeHead(412);
        res.end();
    }
}

function resEndFile(path, res) {
    res.writeHead(200, {"Content-Type": mime.getType(path)});
    return fs.createReadStream(path).pipe(res);
}

function resEndJSON(json, res) {
    res.writeHead(200, {"Content-Type": "application/json"});
    res.end(JSON.stringify(json));
}

function resStartSession(req, res, data) {
    let key = crypto.randomBytes(128).toString("ascii"),
        session = {
            IP: req.IP,
            DOL: Date.now()
        };
    for (let item in data) session[item] = data[item];
    // TODO: session.data = data;
    sessions[key] = session;

    res.setHeader("Cache-Control", "No-Cache, No-Store, Must-Revalidate");
    res.setHeader("Pragma", "No-Cache");
    res.setHeader("Set-Cookie", `s=${encodeURIComponent(key)}; HttpOnly;`);

    console.log("NEW SESSION:", key);
}

function resClearCookie(name, res) {
    res.setHeader("Cache-Control", "No-Cache, No-Store, Must-Revalidate");
    res.setHeader("Pragma", "No-Cache");
    res.setHeader("Set-Cookie", name + "=_DELETED; HttpOnly; Max-Age=-1; Expires=Thu, 01 Jan 1970 00:00:00 GMT;");
}

function foreach(xs, template) {
    let result = "";
    for (let i = 0; i < xs.length; i++) result += template(xs[i], i);
    return result;
}

const DEFAULT_METHODS = ["GET", "POST", "PUT"],
    HELPERS = {
        css() {
            return foreach(arguments, path => `<link href="${path}.css" type="text/css" rel="stylesheet" />`)
        },
        js() {
            return foreach(arguments, path => `<script src="${path}.js" defer></script>`)
        },
        cap: s => s[0].toUpperCase() + s.slice(1),
        foreach: foreach
    },
    __DIRNAME = path.resolve(),
    DEFAULT_PORT = process.env.OPENSHIFT_NODEJS_PORT || process.env.PORT || 80,
    DEFAULT_IP = process.env.OPENSHIFT_NODEJS_IP || "0.0.0.0";


export default class {
    // pool = new Pool(process.env.DATABASE_URL ?
    //     {
    //         connectionString: process.env.DATABASE_URL
    //     } : {
    //         host: "127.0.0.1",
    //         user: "postgres",
    //         database: "unicheap"
    //     }),
    listen(ip = DEFAULT_IP, port = DEFAULT_PORT) {
        console.log(`LISTENING @ http://${ip}:${port}`);
        this._server.listen(port, ip);
    }

    constructor({
                    root = __DIRNAME,
                    methods = DEFAULT_METHODS,
                    templates = path.join(__DIRNAME, "/templates")
                }) {
        const public_path = path.join(__DIRNAME, "public");

        this._sessions = {};
        this._templates = templates;
        this._routes = {};
        this._paramRoutes = {};
        this.router = {}

        this._server = http.createServer((req, res) => {
            req.url = url.parse(req.url);
            console.log(req.method, req.url.pathname);
            let file = path.join(public_path, req.url.pathname);
            fs.stat(file.endsWith("/") ? file + "index.html" : file, (err, stat) => {
                if (!err && stat.isFile()) return resEndFile(file, res);

                req.IP = req.headers['X-Forwarded-For'] || req.connection.remoteAddress;
                req.cookies = {};

                if (req.headers.cookie) {
                    let splitCookies = req.headers.cookie.split(";");
                    for (let i = splitCookies.length; i--;) {
                        const cookieParts = splitCookies[i].split("=");
                        req.cookies[cookieParts[0].trim()] = cookieParts[1];
                    }
                    if (req.cookies.s) {
                        const session = this._sessions[decodeURIComponent(req.cookies.s)];
                        if (session) req.session = session;
                        else this.killSession(req, res);
                    }
                }

                if (!(req.method in this._routes)) this.res404(req, res);
                else if (req.url.pathname in this._routes[req.method]) this.route(req.url.pathname, req, res);
                // TODO: MAKE THIS ATOMIC - move into route function
                else {
                    let reqRoute = req.url.pathname.substring(1).split("/");
                    OUTER:
                        for (let proute in this._paramRoutes[req.method]) {
                            let path = proute.substring(1).split("/");
                            if (reqRoute.length !== path.length) continue;
                            req.params = {};
                            for (let j = path.length; j--;) {
                                let param = path[j],
                                    reqParam = reqRoute[j];
                                if (param.indexOf(":") === 0) req.params[param.substring(1)] = reqParam;
                                else if (param !== reqParam) continue OUTER;
                            }
                            return this.route(proute, req, res);
                        }
                    if ("*" in this._routes[req.method]) this.route("*", req, res);
                    else this.res404(req, res);
                }
            });
        });

        methods.forEach(method => {
            const routeMethod = method.toUpperCase();
            this._routes[routeMethod] = {};
            this._paramRoutes[routeMethod] = {};

            this.router[method.toLowerCase()] = (routePath, ...handlers) => {
                const routeType = routePath.indexOf(":") === -1 ? this._routes : this._paramRoutes;
                routeType[routeMethod][routePath] = handlers;
            }
        })
    }

    killSession(req, res) {
        if (req.cookies.s) delete this._sessions[decodeURIComponent(req.cookies.s)];
        resClearCookie("s", res);
        console.log("SESSION KILLED");
    }

    route(path, req, res) {
        let handler = 0;
        const route = (path.indexOf(":") === -1 ? this._routes : this._paramRoutes)[req.method][path];
        const next = () => route[handler++](req, res, next);

        if (req.method === "GET") next();
        else {
            req.body = {};
            req.files = {};

            const busboy = new Busboy({headers: req.headers});
            busboy.on("file", (fieldname, file) => {
                const buffs = [];
                file.on("data", data => buffs.push(data));
                file.on("end", function () {
                    req.files[fieldname] = Buffer.concat(buffs);
                });
            });
            busboy.on("field", (fieldname, val) => req.body[fieldname] = val);
            busboy.on("finish", next);
            busboy.on("error", err => this.res500(req, res, err));
            req.pipe(busboy);
        }
    }

    render(template, req, res, opts = {}) {
        req.helpers = HELPERS;

        console.log("Render:", template);
        return import(path.join(this._templates, template))
            .then(template => {
                res.writeHead(opts.status || 200, {"Content-Type": "text/html; charset=UTF-8"});
                res.end(template.default(req, res, opts))
            })
        // .catch(error => this.res500(req, res));
    }


    res500(req, res, err) {
        this.render("500", req, res, {status: 500});
        if (err) console.trace(err);
        else console.trace("RES500");
    }

    res404(req, res) {
        this.render("404", req, res, {status: 404});
    }
}

// export default {
//     connection: pool,
//     pool: SQLPool,
//     captcha: captcha,
//     JSONBody: JSONBody,
//     router: router,
//     render: resRender,
//     end500: res500,
//     end404: res404,
//     endJSON: resEndJSON,
//     endFile: resEndFile,
//     clearCookie: resClearCookie,
//     listen: listen,
//     public: PUBLIC,
//     templates: templates,
//     startSession: resStartSession,
//     killSession: resKillSession,
//     endRedirect: resRedirect,
//     helpers: HELPERS
// };