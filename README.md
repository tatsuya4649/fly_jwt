
# fly-jwt

![Test](https://github.com/tatsuya4649/fly_jwt/actions/workflows/test.yaml/badge.svg)

fly-jwt is JWT library for [fly](https://github.com/tatsuya4649/fly).

## Hello World

```python

from fly import Fly
from fly_jwt import require_jwt

app = Fly()

@require_jwt(
    algorithm="HS256",
    private_key="secret",
)
@app.get("/")
def hello(jwt_payload: Request):
    return f"Hello World {jwt_payload["user_id"]}"

```

client send request.

```bash

GET / HTTP1.1
.
. 
.
Authorization: Bearer `JWT CONTENT`

```

if authentication successed, execute `hello` function.

if authentication failed, return 401 response.

# Dependency

* fly

* cryptography

* PyJWT
