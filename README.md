
# JWT for fly

JWT library for [fly web server](https://github.com/tatsuya4649/fly).

## Hello World

```python

from fly import Fly
from fly_jwt import require_jwt, jwt_payload

app = Fly()

@require_jwt(
    algorithm="HS256",
    private_key="secret",
)
@app.get("/")
def hello(request):
    # How to get a JWT payload
    payload = jwt_payload(request)
    return "Hello World"

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
