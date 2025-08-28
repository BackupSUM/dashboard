import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key-change-this")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
SESSION_EXPIRE_DAYS = int(os.getenv("SESSION_EXPIRE_DAYS", "30"))
USERS_FILE = os.getenv("USERS_FILE", "users.json")
SESSIONS_FILE = os.getenv("SESSIONS_FILE", "sessions.json")
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))

# Password hashing with configurable rounds
pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto",
    bcrypt__rounds=BCRYPT_ROUNDS
)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Optional[str]:
    """Verify JWT token and return username if valid."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except JWTError:
        return None

def load_users() -> List[Dict]:
    """Load users from JSON file."""
    if not os.path.exists(USERS_FILE):
        return []
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []

def save_users(users: List[Dict]) -> None:
    """Save users to JSON file."""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def load_sessions() -> Dict:
    """Load sessions from JSON file."""
    if not os.path.exists(SESSIONS_FILE):
        return {}
    try:
        with open(SESSIONS_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def save_sessions(sessions: Dict) -> None:
    """Save sessions to JSON file."""
    with open(SESSIONS_FILE, 'w') as f:
        json.dump(sessions, f, indent=2)

def find_user_by_username(username: str) -> Optional[Dict]:
    """Find user by username."""
    users = load_users()
    for user in users:
        if user.get('username') == username:
            return user
    return None

def find_user_by_email(email: str) -> Optional[Dict]:
    """Find user by email."""
    users = load_users()
    for user in users:
        if user.get('email') == email:
            return user
    return None

def find_user_by_username_or_email(identifier: str) -> Optional[Dict]:
    """Find user by username or email."""
    user = find_user_by_username(identifier)
    if user:
        return user
    return find_user_by_email(identifier)

def create_user(username: str, email: str, password: str) -> bool:
    """Create a new user and save to JSON file."""
    users = load_users()
    
    # Check if user already exists
    if find_user_by_username(username) or find_user_by_email(email):
        return False
    
    # Create new user
    new_user = {
        "username": username,
        "email": email,
        "hashed_password": get_password_hash(password),
        "last_company": None,
        "last_type": None,
        "created_at": datetime.utcnow().isoformat(),
        "last_login": None
    }
    
    users.append(new_user)
    save_users(users)
    return True

def authenticate_user(username_or_email: str, password: str) -> Optional[Dict]:
    """Authenticate user with username/email and password."""
    user = find_user_by_username_or_email(username_or_email)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    
    # Update last login
    update_user_last_login(user["username"])
    return user

def update_user_last_login(username: str) -> bool:
    """Update user's last login timestamp."""
    users = load_users()
    for i, user in enumerate(users):
        if user.get('username') == username:
            users[i]['last_login'] = datetime.utcnow().isoformat()
            save_users(users)
            return True
    return False

def update_user_selection(username: str, company: str = None, type_selection: str = None) -> bool:
    """Update user's last company and/or type selection."""
    users = load_users()
    
    for i, user in enumerate(users):
        if user.get('username') == username:
            if company is not None:
                users[i]['last_company'] = company
                print(f"DEBUG: Updated user {username} company to: {company}")
            if type_selection is not None:
                users[i]['last_type'] = type_selection
                print(f"DEBUG: Updated user {username} type to: {type_selection}")
            save_users(users)
            print(f"DEBUG: User {username} current state: company={users[i].get('last_company')}, type={users[i].get('last_type')}")
            return True
    
    print(f"DEBUG: User {username} not found for update")
    return False

def get_user_selections(username: str) -> Dict:
    """Get user's last company and type selections."""
    user = find_user_by_username(username)
    if user:
        return {
            "username": user.get("username"),
            "last_company": user.get("last_company"),
            "last_type": user.get("last_type"),
            "last_login": user.get("last_login")
        }
    return {"username": None, "last_company": None, "last_type": None, "last_login": None}

def create_session(username: str) -> str:
    """Create a new session for user."""
    sessions = load_sessions()
    session_id = str(uuid.uuid4())
    
    # Clean expired sessions first
    clean_expired_sessions()
    
    sessions[session_id] = {
        "username": username,
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": (datetime.utcnow() + timedelta(days=SESSION_EXPIRE_DAYS)).isoformat(),
        "last_accessed": datetime.utcnow().isoformat()
    }
    
    save_sessions(sessions)
    return session_id

def get_session(session_id: str) -> Optional[Dict]:
    """Get session data by session ID."""
    if not session_id:
        return None
        
    sessions = load_sessions()
    session = sessions.get(session_id)
    
    if not session:
        return None
    
    # Check if session expired
    expires_at = datetime.fromisoformat(session["expires_at"])
    if datetime.utcnow() > expires_at:
        # Remove expired session
        del sessions[session_id]
        save_sessions(sessions)
        return None
    
    # Update last accessed
    session["last_accessed"] = datetime.utcnow().isoformat()
    sessions[session_id] = session
    save_sessions(sessions)
    
    return session

def delete_session(session_id: str) -> bool:
    """Delete a session."""
    sessions = load_sessions()
    if session_id in sessions:
        del sessions[session_id]
        save_sessions(sessions)
        return True
    return False

def clean_expired_sessions() -> int:
    """Clean all expired sessions."""
    sessions = load_sessions()
    current_time = datetime.utcnow()
    expired_sessions = []
    
    for session_id, session in sessions.items():
        expires_at = datetime.fromisoformat(session["expires_at"])
        if current_time > expires_at:
            expired_sessions.append(session_id)
    
    for session_id in expired_sessions:
        del sessions[session_id]
    
    if expired_sessions:
        save_sessions(sessions)
    
    return len(expired_sessions)

def has_complete_profile(username: str) -> bool:
    """Check if user has completed company and type selection."""
    user = find_user_by_username(username)
    if not user:
        return False
    
    return (user.get("last_company") is not None and 
            user.get("last_type") is not None)

def check_database_connection() -> bool:
    """Check if database connection is available."""
    try:
        from DB.temp_db import get_database
        db = get_database()
        return True
    except ImportError:
        return False
    except Exception:
        return False

def get_database_status() -> Dict:
    """Get database status information."""
    try:
        from DB.temp_db import get_database
        db = get_database()
        return {
            "available": True,
            "message": "Database connection active",
            "credentials_file": "DB\credentials.json"
        }
    except ImportError:
        return {
            "available": False,
            "message": "Database module not installed",
            "error": "Missing DB.temp_db module"
        }
    except FileNotFoundError as e:
        return {
            "available": False,
            "message": "Credentials file not found",
            "error": str(e)
        }
    except Exception as e:
        return {
            "available": False,
            "message": "Database connection failed",
            "error": str(e)
        }