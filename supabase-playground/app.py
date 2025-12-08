import os
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from supabase import create_client, Client
from typing import Optional

# 1. Load Environment Variables
load_dotenv()

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")

# 2. Initialize Supabase Client
supabase: Client = create_client(url, key)

app = FastAPI(title="FastAPI + Supabase Auth")

# 3. Define Pydantic Models for Request Bodies
class UserSchema(BaseModel):
    email: str
    password: str

# 4. Authentication Dependency
# This function verifies the JWT token in the Authorization header
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    
    try:
        # We use Supabase to verify the token. 
        # This checks if the token is valid and not expired.
        user_response = supabase.auth.get_user(token)
        
        if not user_response or not user_response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user_response.user

    except Exception as e:
        # If Supabase returns an error (e.g., expired token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

# --- Routes ---

@app.get("/")
def read_root():
    return {"message": "Welcome to FastAPI + Supabase Auth Example"}

@app.post("/signup")
def sign_up(user_data: UserSchema):
    try:
        # Create user in Supabase Auth
        response = supabase.auth.sign_up({
            "email": user_data.email,
            "password": user_data.password
        })
        return {"message": "User created successfully", "user": response.user}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login")
def login(user_data: UserSchema):
    try:
        # Sign in and get JWT Access Token
        response = supabase.auth.sign_in_with_password({
            "email": user_data.email,
            "password": user_data.password
        })
        
        return {
            "access_token": response.session.access_token,
            "token_type": "bearer",
            "expires_in": response.session.expires_in
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

# 5. Protected Route
@app.get("/protected")
def protected_route(user = Depends(get_current_user)):
    """
    This route is only accessible if a valid JWT is provided.
    The 'user' object contains data from Supabase Auth.
    """
    return {
        "message": "You have accessed a protected route!",
        "user_email": user.email,
        "user_id": user.id
    }