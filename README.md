
# JWT for fly

JWT library for [fly web server](https://github.com/tatsuya4649/fly).

## Hello World

```
from fly import Fly
from fly_jwt import require_jwt

app = Fly()

@require_jwt(
    algorithm="HS256",
	private_key_path="conf/server.key",
)
@app.get("/")
def hello(request):
    return "Hello World"
```

client send request.

```
GET / HTTP1.1
.
.
.
Authorization: Bearer `JWT CONTENT`
```

if authentication successed, execute `hello` function.

if authentication failed, return 401 response.

