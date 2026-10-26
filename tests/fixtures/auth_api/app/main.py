"""Token-login target. Credentials: admin / admin123.

  POST /auth/login    JSON {username, password} -> {"access_token": ...}; 401 on bad credentials
  POST /auth/logout   decoy: must never be mistaken for the login endpoint
  GET  /public/ping   no auth
  GET  /secure/{a,b,c,d}   need the *latest* issued token, and each token serves only AUTH_API_TOKEN_LIMIT
                           authenticated requests (then 401) -> exercises re-login
"""

import os

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Auth API", version="1.0.0")
LIMIT = int(os.environ.get("AUTH_API_TOKEN_LIMIT", "100000"))
STATE = {"serial": 0, "token": None, "uses": 0}


class LoginBody(BaseModel):
    username: str
    password: str


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or authorization != f"Bearer {STATE['token']}":
        raise HTTPException(status_code=401, detail="Not authenticated")
    STATE["uses"] += 1
    if STATE["uses"] > LIMIT:
        raise HTTPException(status_code=401, detail="Token expired")
    return {"id": 1}


@app.post("/auth/login")
def login(body: LoginBody) -> dict:
    if (body.username, body.password) != ("admin", "admin123"):
        raise HTTPException(status_code=401, detail="Bad credentials")
    STATE["serial"] += 1
    STATE["token"], STATE["uses"] = f"tok-{STATE['serial']}-abcdefgh", 0
    return {"access_token": STATE["token"], "token_type": "bearer"}


@app.post("/auth/logout")
def logout() -> dict:
    return {"ok": True}


@app.get("/public/ping")
def ping() -> dict:
    return {"pong": True}


@app.get("/secure/a")
def secure_a(user: dict = Depends(get_current_user)) -> dict:
    return {"name": "a"}


@app.get("/secure/b")
def secure_b(user: dict = Depends(get_current_user)) -> dict:
    return {"name": "b"}


@app.get("/secure/c")
def secure_c(user: dict = Depends(get_current_user)) -> dict:
    return {"name": "c"}


@app.get("/secure/d")
def secure_d(user: dict = Depends(get_current_user)) -> dict:
    return {"name": "d"}
