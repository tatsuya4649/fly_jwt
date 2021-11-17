import sys
import os
sys.path.append(
    os.path.abspath("../fly")
)
from fly import Fly
from fly_jwt import require_jwt
from fly_jwt import jwt


app = Fly()

def auth(info):
    return

@require_jwt(
    auth_handler=auth,
    algorithm="RS256",
    public_key_path="conf/server.pub",
    private_key_path="conf/server.key",
)
@app.get("/")
def hello(request):
    pass

jwt.__fly_jwt({"header": [{"name": "authorization", "value": "Bearer afdsfas"}]})
