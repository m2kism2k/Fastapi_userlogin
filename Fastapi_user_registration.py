from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from database import User, Department, Role, get_db, init_db

init_db()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# class RegisterRequest(BaseModel):
   # username: str
    #password: str
    #department: str
    #role: str

def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_or_create_department(db: Session, name: str):
    dept = db.query(Department).filter(Department.name == name).first()
    if not dept:
        dept = Department(name=name)
        db.add(dept)
        db.commit()
        db.refresh(dept)
    return dept

def get_or_create_role(db: Session, name: str):
    role = db.query(Role).filter(Role.name == name).first()
    if not role:
        role = Role(name=name)
        db.add(role)
        db.commit()
        db.refresh(role)
    return role

app = FastAPI()

#@app.post("/register")
#def register(request: RegisterRequest, db: Session = Depends(get_db)):
 #   username = request.username
  #  password = request.password
   # department = request.department
    #role = request.role

@app.post("/register")
def register(username: str, password: str, department: str, role: str, db: Session = Depends(get_db)):
    if get_user(db, username):
        raise HTTPException(status_code=400, detail="Username already registered")

    db_department = db.query(Department).filter(Department.name == department).first()
    if not db_department:
        db_department = Department(name=department)
        db.add(db_department)
        db.commit()
        db.refresh(db_department)

    db_role = db.query(Role).filter(Role.name == role).first()
    if not db_role:
        db_role = Role(name=role)
        db.add(db_role)
        db.commit()
        db.refresh(db_role)

    # user with foreign keys
    user = User(
        username=username,
        hashed_password=get_password_hash(password),
        department_id=db_department.id,
        role_id=db_role.id
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "msg": "User registered successfully",
        "username": user.username,
        "department": db_department.name,
        "role": db_role.name
    }

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "department": user.department.name if user.department else None,
        "role": user.role.name if user.role else None
    }
