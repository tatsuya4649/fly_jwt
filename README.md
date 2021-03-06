
# fly-jwt

![Test](https://github.com/tatsuya4649/fly_jwt/actions/workflows/test.yaml/badge.svg)

fly-jwt is JWT library for [fly](https://github.com/tatsuya4649/fly).

## Hello World

```python

from fly import Fly
from fly.types import Request
from fly_jwt import require_jwt

app = Fly()

def auth_handler(payload):
    return payload["username"] is "test_user"

@app.get("/")
@require_jwt(
    algorithm="HS256",
    private_key="secret",
    auth_handler=auth_handler
)
def hello(jwt_payload: Request):
    return f"Hello World {jwt_payload["username"]}"

```

client send request.

```bash

GET / HTTP1.1
.
. 
.
Authorization: Bearer `JWT TOKEN`

```

if authentication successed, execute `hello` function.

if authentication failed, return 401 response.

# Dependency

* fly >= 1.3.0

* cryptography

* PyJWT
