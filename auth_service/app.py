# auth_service/app.py

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import jwt
import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()


class TokenData(BaseModel):
    token: str


app = FastAPI(title="Authentication Service")

# Database connection
def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST"),
        database=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        sslmode='require'  # required for Neon
    )


# Models
class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    name: str
    role: str = "customer"  # Default role is customer

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    role: str
    name: str

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 3600  # 1 hour

# Routes
@app.post("/login", response_model=TokenResponse)
async def login(user_data: UserLogin):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Find user by email
    cursor.execute("SELECT * FROM users WHERE email = %s", (user_data.email,))
    user = cursor.fetchone()
    
    if not user:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Verify password
    if not bcrypt.checkpw(user_data.password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        cursor.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Create JWT token
    token_data = {
        "sub": str(user["id"]),
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXPIRATION)
    }
    token = jwt.encode(token_data, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    cursor.close()
    conn.close()
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user["id"],
        "role": user["role"],
        "name": user["name"]
    }

@app.post("/register", response_model=TokenResponse)
async def register(user_data: UserRegister):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Check if email already exists
    cursor.execute("SELECT id FROM users WHERE email = %s", (user_data.email,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    password_hash = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Insert new user
    cursor.execute(
        "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, %s) RETURNING *",
        (user_data.name, user_data.email, password_hash, user_data.role)
    )
    user = cursor.fetchone()
    conn.commit()
    
    # Create JWT token
    token_data = {
        "sub": str(user["id"]),
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXPIRATION)
    }
    token = jwt.encode(token_data, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    cursor.close()
    conn.close()
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user["id"],
        "role": user["role"],
        "name": user["name"]
    }

@app.post("/verify")
async def verify_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {"valid": True, "user": payload}
    except jwt.ExpiredSignatureError:
        return {"valid": False, "reason": "expired"}
    except jwt.InvalidTokenError as e:
        return {"valid": False, "reason": str(e)}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)