import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db

import base64, hmac, hashlib, json, time

# Simple built-in JWT (HS256) helpers to avoid external deps
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def jwt_encode(payload: dict, key: str, algorithm: str = "HS256") -> str:
    header = {"alg": algorithm, "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(',',':')).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(',',':')).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"

def jwt_decode(token: str, key: str, algorithms: list[str] = ["HS256"]) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split('.')
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token format")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_sig, _b64url_decode(sig_b64)):
        raise HTTPException(status_code=401, detail="Invalid token signature")
    payload = json.loads(_b64url_decode(payload_b64))
    # exp check
    exp = payload.get('exp')
    if exp is not None and time.time() > exp:
        raise HTTPException(status_code=401, detail="Token expired")
    return payload

# ENV
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

app = FastAPI(title="HabitPilot API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ----------------------- Models -----------------------
class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    plan: str

class HabitIn(BaseModel):
    name: str
    frequency: str = "daily"

class HabitOut(BaseModel):
    id: str
    name: str
    frequency: str
    streak: int

class HabitLogIn(BaseModel):
    habit_id: str
    date: str
    note: Optional[str] = None

# ----------------------- Utils -----------------------

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire_dt = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": int(expire_dt.timestamp())})
    return jwt_encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str):
    return jwt_decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def get_user_by_email(email: str):
    return db.user.find_one({"email": email})


def get_user_by_id(user_id: str):
    try:
        return db.user.find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except HTTPException:
        raise
    except Exception:
        raise credentials_exception
    user = get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    return user

# ----------------------- Auth -----------------------
@app.post("/auth/register", response_model=UserOut)
def register(user: UserCreate):
    if get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(user.password)
    doc = {
        "name": user.name,
        "email": user.email,
        "password_hash": hashed,
        "plan": "free",
        "created_at": datetime.now(timezone.utc),
    }
    res_id = db.user.insert_one(doc).inserted_id
    return {"id": str(res_id), "name": doc["name"], "email": doc["email"], "plan": doc["plan"]}


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": str(user["_id"])})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/auth/me", response_model=UserOut)
def me(current_user: dict = Depends(get_current_user)):
    return {
        "id": str(current_user["_id"]),
        "name": current_user["name"],
        "email": current_user["email"],
        "plan": current_user.get("plan", "free"),
    }

# ----------------------- Habits -----------------------
@app.post("/habits", response_model=HabitOut)
def create_habit(habit: HabitIn, user: dict = Depends(get_current_user)):
    doc = {
        "user_id": str(user["_id"]),
        "name": habit.name,
        "frequency": habit.frequency,
        "created_at": datetime.now(timezone.utc),
    }
    hid = db.habit.insert_one(doc).inserted_id
    return {"id": str(hid), "name": doc["name"], "frequency": doc["frequency"], "streak": 0}


@app.get("/habits", response_model=List[HabitOut])
def list_habits(user: dict = Depends(get_current_user)):
    items = []
    for h in db.habit.find({"user_id": str(user["_id"])}, sort=[("created_at", -1)]):
        streak = db.habitlog.count_documents({"habit_id": str(h["_id"])})
        items.append({"id": str(h["_id"]), "name": h["name"], "frequency": h.get("frequency", "daily"), "streak": streak})
    return items


@app.post("/habits/log")
def log_habit(entry: HabitLogIn, user: dict = Depends(get_current_user)):
    habit = db.habit.find_one({"_id": ObjectId(entry.habit_id), "user_id": str(user["_id"])})
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    doc = {"habit_id": entry.habit_id, "user_id": str(user["_id"]), "date": entry.date, "note": entry.note, "created_at": datetime.now(timezone.utc)}
    db.habitlog.insert_one(doc)
    return {"ok": True}

# ----------------------- Payments (lazy import Stripe) -----------------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
PRICE_ID = os.getenv("STRIPE_PRICE_ID", "price_dummy_monthly")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

class CreateCheckoutSessionRequest(BaseModel):
    success_url: Optional[str] = None
    cancel_url: Optional[str] = None

@app.post("/billing/create-checkout-session")
def create_checkout_session(body: CreateCheckoutSessionRequest, user: dict = Depends(get_current_user)):
    try:
        import stripe
        if not STRIPE_SECRET_KEY:
            raise RuntimeError("No Stripe key; using mock")
        stripe.api_key = STRIPE_SECRET_KEY
        success = body.success_url or FRONTEND_URL + "/dashboard?upgrade=success"
        cancel = body.cancel_url or FRONTEND_URL + "/dashboard?upgrade=cancel"
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": PRICE_ID, "quantity": 1}],
            success_url=success,
            cancel_url=cancel,
            customer_email=user["email"],
            metadata={"user_id": str(user["_id"])},
        )
        return {"id": session.id, "url": session.url}
    except Exception:
        return {"id": "mock_session", "url": (body.success_url or FRONTEND_URL) + "/dashboard?upgrade=mock"}

@app.post("/billing/webhook")
async def stripe_webhook(request: Request):
    return {"received": True}

# ----------------------- Health -----------------------
@app.get("/")
def root():
    return {"message": "HabitPilot API running"}

@app.get("/test")
def test_database():
    info = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            info["database"] = "✅ Available"
            info["database_url"] = "✅ Set"
            info["database_name"] = db.name
            info["connection_status"] = "Connected"
            info["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        info["database"] = f"Error: {str(e)[:80]}"
    return info

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
