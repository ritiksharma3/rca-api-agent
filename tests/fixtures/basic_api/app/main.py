"""HTTP Basic target. Credentials: admin / admin123.

  GET /basic/me   needs Authorization: Basic base64(admin:admin123)
"""

import base64

from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI(title="Basic API", version="1.0.0")
EXPECTED = "Basic " + base64.b64encode(b"admin:admin123").decode()


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    if authorization != EXPECTED:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"id": 1}


@app.get("/basic/me")
def me(user: dict = Depends(get_current_user)) -> dict:
    return user
