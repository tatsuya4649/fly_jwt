import jwt
import re
from .config import _JWTConfig
from fly import Fly
from fly.exceptions import HTTPException, HTTP401Exception, HTTP500Exception
from fly.response import Response

def _re_bearer(header_value):
    res = re.match(r'^Bearer (.+)$', header_value)
    if res is not None and len(res.groups()) == 1:
        return res[1]
    else:
        return None

def _fly_jwt(request):
    _conf = _fly_jwt._jwt_config
    _debug = _fly_jwt._debug
    _auth = _conf.auth_handler
    _func = _conf.success_handler
    if _func is None:
        raise ValueError("Unknown success handler")

    try:
        _jwt = FlyJWT(_conf)
        if request.get("header") is None:
            raise HTTP401Exception(
                    "fly_jwt must have header key in dict of request"
                    )
        for item in request["header"]:
            if item["name"] == "Authorization" or \
                    item["name"] == "authorization":
                encoded = _re_bearer(item["value"])
                if encoded is None:
                    raise HTTP401Exception("There is no fly_jwt token in `Authorization: Bear $token$`.")
                try:
                    decoded = _jwt.decode(encoded)
                except jwt.PyJWTError as e:
                    raise HTTP401Exception(str(e))
                except Exception as e:
                    raise Exception(str(e))
                try:
                    res = _auth(decoded)
                    if res is None or not isinstance(res, bool):
                        raise TypeError("Return type must be bool type.")
                    if not res:
                        raise HTTP401Exception("Authentication failure")
                    else:
                        # Successful authentication !
                        return _func(request)
                except HTTP401Exception as e:
                    raise HTTP401Exception(str(e))
                except Exception as e:
                    raise Exception(f"Authentication handler error: {str(e)}")
                request["jwt_content"] = decoded

        raise HTTP401Exception("Not found Authorization item in HTTP request header.")
    except HTTP401Exception as e:
        _fail = _conf.fail_handler
        if _fail is None:
            res = Response(
                status_code=401,
                body=str(e).encode("utf-8") if _debug else None,
            )
            return res
        else:
            try:
                return _fail(str(e))
            except HTTPException as e:
                res = Response(
                    status_code=e.status_code,
                    header=e.headers,
                    body=str(e).encode("utf-8") if _debug else None,
                )
                return res
            except Exception as e:
                res = Response(
                    status_code=500,
                    body=str(e).encode("utf-8") if _debug else None,
                )
                return res
    except Exception as e:
        res = Response(
            status_code=500,
            body=str(e).encode("utf-8") if _debug else None,
        )
        return res

def require_jwt(
    **kwargs
):
    def _jwt(func):
        _conf = _JWTConfig(func, **kwargs)

        if not hasattr(func, "_application"):
            raise ValueError(
"""

    \"require_jwt\" must call after app.route(get, post, etc...) decorator.

    ex.
        @route_jwt(
            algorithm=\"HS256\",
            private_key_path="conf/server.key"
        )
        @app.get("/")
        def index(request):
            return \"Hello World\"
"""
            )

        app = func._application
        if app.__class__ is not Fly:
            raise ValueError(
                "invalid Fly instance"
            )
        route = func.route
        app._change_route(
            route["uri"],
            route["method"],
            _fly_jwt
        )
        setattr(_fly_jwt, "_jwt_config", _conf)
        setattr(_fly_jwt, "_debug", app.is_debug)
        return func

    return _jwt

def require_jwt_conf(conf):
    pass


class FlyJWT:
    def __init__(self, conf):
        if not isinstance(conf, _JWTConfig):
            raise TypeError("FlyJWT must pass _JWTConfig instance.")

        self._conf = conf

    def decode(self, encoded):
        return jwt.decode(
            encoded,
            self._conf.private_key \
                    if self._conf._symmetric else \
                    self._conf.public_key,
            algorithms=[self._conf.algorithm],
        )
