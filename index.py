#FastAPI for CRUD of users and items in a database

import dotenv
import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, List
from jose import JWTError, jwt
from datetime import datetime, timedelta, date
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import User, Item
from schemas import UserCreate, ItemCreate, User, Item, Token, TokenData
from crud import get_user, get_user_by_id, get_user_items, create_user, create_user_item
from security import get_db, authenticate_user, create_access_token, get_current_user, get_current_active_user

SECRET_KEY = "d6f8a6d8f6a8d6f8a6d8f6a8d6f8a6d8f6a8d6f8a6d8f6a8d6f8a6d8f6a8d6f"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

dotenv.load_dotenv()

app = FastAPI()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
    
# Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Hashing password
def get_password_hash(password):
    return pwd_context.hash(password)

# Verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Create access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Get current user
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db=SessionLocal(), username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# Get current active user
async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Create user
@app.post("/users/", response_model=User)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    return create_user(db=db, user=user)

# Get user
@app.get("/users/{username}", response_model=User)
def read_user(username: str, db: Session = Depends(get_db)):
    db_user = get_user(db, username=username)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

# Get token
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Create item
@app.post("/items/", response_model=Item)
def create_item_for_user(item: ItemCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    return create_user_item(db=db, item=item, user_id=current_user.id)

# Get item
@app.get("/items/", response_model=List[Item])
def read_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    items = get_user_items(db, user_id=current_user.id, skip=skip, limit=limit)
    return items

# Get user items
@app.get("/users/{username}/items/", response_model=List[Item])
def read_user_items(username: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    db_user = get_user(db, username=username)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    items = get_user_items(db, user_id=db_user.id, skip=skip, limit=limit)
    return items

# Get user by id
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

# Get user by id
@app.get("/users/me/items/", response_model=List[Item])
async def read_own_items(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    items = get_user_items(db, user_id=current_user.id)
    return items

# Run
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port={os.getenv("APP_DOCKER_PORT", 8000)})