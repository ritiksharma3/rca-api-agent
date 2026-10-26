"""Small FastAPI app with known routes and predictable behaviour, used as the end-to-end target.

Route behaviour (see tests/integration):
  GET  /health            passes
  GET  /items             passes (query: limit)
  GET  /items/{item_id}   needs a fixture value for item_id (otherwise BLOCKED)
  POST /items             mutating; validates body
  GET  /users/me          requires a bearer token (token: demo-token)
  GET  /stats             documented schema {total:int} but returns {"total": "oops"}  -> FAIL
  /dyn/*                  registered dynamically; static analysis cannot discover them -> NOT DISCOVERED
"""

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Sample API", version="1.0.0")
router = APIRouter(prefix="/items", tags=["items"])

ITEMS = {1: {"id": 1, "name": "widget", "price": 9.5, "tags": []}}


class ItemCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    price: float = Field(..., ge=0)
    tags: list[str] = []


class Item(BaseModel):
    id: int
    name: str
    price: float
    tags: list[str] = []


class Stats(BaseModel):
    total: int


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    if authorization != "Bearer demo-token":
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"id": 1, "name": "demo"}


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("", response_model=list[Item])
def list_items(limit: int = 10):
    return list(ITEMS.values())[:limit]


@router.get("/{item_id}", response_model=Item)
def get_item(item_id: int):
    if item_id not in ITEMS:
        raise HTTPException(status_code=404, detail="not found")
    return ITEMS[item_id]


@router.post("", response_model=Item, status_code=201)
def create_item(item: ItemCreate):
    new_id = max(ITEMS) + 1
    ITEMS[new_id] = {"id": new_id, **item.model_dump()}
    return ITEMS[new_id]


@app.get("/users/me")
def read_me(user: dict = Depends(get_current_user)):
    return user


@app.get("/stats", response_model=Stats)
def stats():
    return JSONResponse({"total": "oops"})  # bypasses response_model validation on purpose


app.include_router(router)

for _name in ("alpha", "beta"):
    app.add_api_route(f"/dyn/{_name}", lambda: {"ok": True}, methods=["GET"])
