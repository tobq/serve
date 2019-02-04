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
            if (err) res500(req, res, err);
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
        if (err) return res500(req, res, err);
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

function route(path, req, res) {
    function next() {
        route[routerIndex++](req, res, next)
    }

    let routerIndex = 0,
        route = (path.indexOf(":") === -1 ? router : router.param)[req.method][path];

    if (req.method === "GET") next();
    else {
        req.body = {};
        req.files = {};

        const busboy = new Busboy({headers: req.headers});
        busboy.on("file", function (fieldname, file, filename, encoding, mimetype) {
            const buffs = [];
            file.on("data", data => buffs.push(data));
            file.on("end", function () {
                req.files[fieldname] = Buffer.concat(buffs);
            });
        });
        busboy.on("field", function (fieldname, val, fieldnameTruncated, valTruncated, encoding, mimetype) {
            req.body[fieldname] = val;
        });
        busboy.on("finish", function () {
            console.log(req.body, req.files);
            next();
        });
        busboy.on("error", function (err) {
            res500(req, res, err)
        });
        req.pipe(busboy);
    }
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

function resRender(path, req, res, opts) {
    if (!opts) opts = {};
    req.helpers = HELPERS;

    console.log("Render:", path);
    return import("./templates/" + path)
        .then(template => {
            res.writeHead(opts.status || 200, {"Content-Type": "text/html; charset=UTF-8"});
            res.end(template.default(req, res, opts))
        })
        // .catch(error => res500(req, res));
}


function res500(req, res, err) {
    resRender("500", req, res, {status: 500});
    if (err) console.trace(err);
    else console.trace("RES500");
}

function res404(req, res) {
    resRender("404", req, res, {status: 404});
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

const DEFAULT_METHODS = ["get", "post", "put"],
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


    constructor(root = __DIRNAME, methods = DEFAULT_METHODS) {
        const public_path = path.join(__DIRNAME, "public");

        this._sessions = {};
        this._router = {param: {}};

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

                if (!(req.method in this._router)) res404(req, res);
                else if (req.url.pathname in this._router[req.method]) route(req.url.pathname, req, res);
                else {
                    let reqRoute = req.url.pathname.substring(1).split("/");
                    OUTER:
                        for (let proute in this._router.param[req.method]) {
                            let path = proute.substring(1).split("/");
                            if (reqRoute.length !== path.length) continue;
                            req.params = {};
                            for (let j = path.length; j--;) {
                                let param = path[j],
                                    reqParam = reqRoute[j];
                                if (param.indexOf(":") === 0) req.params[param.substring(1)] = reqParam;
                                else if (param !== reqParam) continue OUTER;
                            }
                            return route(proute, req, res);
                        }
                    if ("*" in this._router[req.method]) route("*", req, res);
                    else res404(req, res);
                }
            });
        });

        for (let method of methods) {
            this._router[method.toUpperCase()] = {};
            this._router.param[method.toUpperCase()] = {};
            this._router[method.toLowerCase()] = function (method, route) {
                const handlers = Array.prototype.slice.call(arguments, 2);
                if (route.indexOf(":") === -1) this._router[method][route] = handlers;
                else this._router.param[method][route] = handlers;
            }.bind(null, method.toUpperCase());
        }
    }

    killSession(req, res) {
        if (req.cookies.s) delete this._sessions[decodeURIComponent(req.cookies.s)];
        resClearCookie("s", res);
        console.log("SESSION KILLED");
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