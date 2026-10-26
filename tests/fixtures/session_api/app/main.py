"""Cookie-session target. Credentials: admin / admin123.

  POST /session/login  JSON {username, password} -> sets cookie sid; 401 on bad credentials
  GET  /session/me     needs the sid cookie
"""

from fastapi import Cookie, Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="Session API", version="1.0.0")
SID = "sess-value-abcdef123456"


class LoginBody(BaseModel):
    username: str
    password: str


def get_current_user(sid: str | None = Cookie(default=None)) -> dict:
    if sid != SID:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"id": 1}


@app.post("/session/login")
def login(body: LoginBody):
    if (body.username, body.password) != ("admin", "admin123"):
        raise HTTPException(status_code=401, detail="Bad credentials")
    resp = JSONResponse({"ok": True})
    resp.set_cookie("sid", SID)
    return resp


@app.get("/session/me")
def me(user: dict = Depends(get_current_user)) -> dict:
    return user
