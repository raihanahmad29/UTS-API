#Nama   : Raihan Fadhilah Ahmad
#NIM    : 18219111

import json
import uvicorn

from datetime import datetime, timedelta
from typing import Optional
from os import write

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "asdf": {
        "username": "asdf",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$Ka0vMpyiiM/W.uIJAb.W9OJrqBrUddCjipFRFyyi5Hj68fWnr6Cvq",
        "disabled": False,
    },
    "Raihan": {
        "username": "Raihan",
        "full_name": "Raihan Ahmad",
        "email": "raihan@gmail.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    },
    "Ahmad": {
        "username": "Ahmad",
        "full_name": "Fadhilah Ahmad",
        "email": "ahmad@gmail.com",
        "hashed_password": "$2b$12$uSVPq0o43flxPyzcbW4q3.y9ChpOmWHYxsQJ276UiUQC5pHHItjRK",
        "disabled": True,
    },
}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

with open("menu.json","r") as read_file:
	data = json.load(read_file)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated = "auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_token(token: str = Depends(oauth2_scheme)):
    return token

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
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(
			status_code=400,
			detail="Inactive user"
		)
    return current_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
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

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/")
def root(current_user: User = Depends(get_current_active_user)):
	return{'Menu','Item'}

@app.get("/menu")
async def read_menus(current_user: User = Depends(get_current_active_user)):
	return data

@app.get("/menu/{item_id}")
async def read_menu(item_id : int, current_user: User = Depends(get_current_active_user)):
	for menu_item in data['menu']:
		if menu_item['id'] == item_id:
			return menu_item
	raise HTTPException(
			status_code = 404,
			detail = f'Item not found'
		)

@app.post('/menu')
async def add_menu(name : str, current_user: User = Depends(get_current_active_user)):
	id = 1
	if(len(data['menu']) > 0):
		id = data['menu'][len(data['menu']) - 1]['id']+1
	n_data = {'id': id,'name' : name}
	data['menu'].append(dict(n_data))
	read_file.close()
	with open("menu.json","w") as write_file:
		json.dump(data,write_file,indent = 4)
	write.file.close()
		
	return n_data

@app.put("/menu/{item_id}")
async def update_menu(item_id : int, name : str, current_user: User = Depends(get_current_active_user)):
	for menu_item in data['menu']:
		if menu_item['id'] == item_id:
			menu_item['name'] = name
			read_file.close()
			with open("menu.json","w") as write_file:
				json.dump(data,write_file,indent = 4)
			write.file.close()

			return("message : data updated successfully!!")

	raise HTTPException(
			status_code = 404,
			detail = f'Item not found'
		)


@app.delete("/menu/{item_id}")
async def delete_menu(item_id : int, current_user: User = Depends(get_current_active_user)):
	for menu_item in data['menu']:
		if menu_item['id'] == item_id:
			data['menu'].remove(menu_item)
			read_file.close()
			with open("menu.json","w") as write_file:
				json.dump(data,write_file,indent = 4) 
			write.file.close()

			return("message : data deleted successfully!!")

	raise HTTPException(
			status_code = 404,
			detail = f'Item not found'
		)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)
