from fastapi import APIRouter, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from datetime import timedelta
import re
from utils import (
    create_user, 
    authenticate_user,  
    create_access_token, 
    verify_token,
    update_user_selection,
    get_user_selections,
    create_session,
    get_session,
    delete_session,
    has_complete_profile,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")

def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username: str) -> str:
    """Validate username and return error message if invalid."""
    username = username.strip()
    if len(username) < 3:
        return "Username must be at least 3 characters long"
    if len(username) > 20:
        return "Username must be less than 20 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return "Username can only contain letters, numbers, and underscores"
    return ""

def validate_password(password: str) -> str:
    """Validate password and return error message if invalid."""
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if len(password) > 100:
        return "Password is too long"
    if not re.search(r'[A-Za-z]', password):
        return "Password must contain at least one letter"
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one number"
    return ""

@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Root endpoint - check for existing session."""
    # Check for existing session
    session_id = request.cookies.get("session_id")
    if session_id:
        session = get_session(session_id)
        if session:
            username = session["username"]
            if has_complete_profile(username):
                return RedirectResponse(url="/dashboard")
            else:
                return RedirectResponse(url="/company")
    
    # No valid session, redirect to login
    return RedirectResponse(url="/login")

@router.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    """Display signup page."""
    return templates.TemplateResponse("signup.html", {"request": request})

@router.post("/signup")
async def signup(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    """Process signup form."""
    # Validate username
    username_error = validate_username(username)
    if username_error:
        return templates.TemplateResponse(
            "signup.html", 
            {
                "request": request, 
                "error": username_error,
                "username": username.strip(),
                "email": email.strip()
            }
        )
    
    # Validate email
    email = email.strip()
    if not validate_email(email):
        return templates.TemplateResponse(
            "signup.html", 
            {
                "request": request, 
                "error": "Please enter a valid email address",
                "username": username.strip(),
                "email": email
            }
        )
    
    # Validate password
    password_error = validate_password(password)
    if password_error:
        return templates.TemplateResponse(
            "signup.html", 
            {
                "request": request, 
                "error": password_error,
                "username": username.strip(),
                "email": email
            }
        )
    
    # Create user
    if create_user(username.strip(), email, password):
        return RedirectResponse(url="/login?message=Account created successfully! Please sign in.", status_code=303)
    else:
        return templates.TemplateResponse(
            "signup.html", 
            {
                "request": request, 
                "error": "Username or email already exists. Please choose different credentials.",
                "username": username.strip(),
                "email": email
            }
        )

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, message: str = None):
    """Display login page."""
    # Check for existing session
    session_id = request.cookies.get("session_id")
    if session_id:
        session = get_session(session_id)
        if session:
            username = session["username"]
            if has_complete_profile(username):
                return RedirectResponse(url="/dashboard")
            else:
                return RedirectResponse(url="/company")
    
    return templates.TemplateResponse(
        "login.html", 
        {
            "request": request, 
            "message": message
        }
    )

@router.post("/login")
async def login(
    request: Request,
    username_or_email: str = Form(...),
    password: str = Form(...)
):
    """Process login form."""
    # Basic validation
    username_or_email = username_or_email.strip()
    if not username_or_email:
        return templates.TemplateResponse(
            "login.html", 
            {
                "request": request, 
                "error": "Please enter your username or email"
            }
        )
    
    if not password:
        return templates.TemplateResponse(
            "login.html", 
            {
                "request": request, 
                "error": "Please enter your password",
                "username_or_email": username_or_email
            }
        )
    
    user = authenticate_user(username_or_email, password)
    
    if not user:
        return templates.TemplateResponse(
            "login.html", 
            {
                "request": request, 
                "error": "Invalid username/email or password. Please try again.",
                "username_or_email": username_or_email
            }
        )
    
    # Create session
    session_id = create_session(user["username"])
    
    # Determine redirect URL based on profile completeness
    if has_complete_profile(user["username"]):
        redirect_url = "/dashboard"
    else:
        redirect_url = "/company"
    
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        max_age=30 * 24 * 60 * 60,  # 30 days
        secure=False,  # Set to True in production with HTTPS
        samesite="lax"
    )
    
    return response

@router.get("/company", response_class=HTMLResponse)
async def company_page(request: Request):
    """Protected company selection page."""
    # Check session
    session_id = request.cookies.get("session_id")
    if not session_id:
        return RedirectResponse(url="/login")
    
    session = get_session(session_id)
    if not session:
        response = RedirectResponse(url="/login")
        response.delete_cookie("session_id")
        return response
    
    username = session["username"]
    
    # Show company selection page
    return templates.TemplateResponse(
        "company.html", 
        {
            "request": request, 
            "username": username
        }
    )

@router.get("/type", response_class=HTMLResponse)
async def type_page(request: Request, company: str = None):
    """Protected type selection page."""
    # Check session
    session_id = request.cookies.get("session_id")
    if not session_id:
        return RedirectResponse(url="/login")
    
    session = get_session(session_id)
    if not session:
        response = RedirectResponse(url="/login")
        response.delete_cookie("session_id")
        return response
    
    username = session["username"]
    # print(f"DEBUG: Type page - username: {username}, company param: {company}")
    
    # If no company specified, redirect to company selection
    if not company:
        # print("DEBUG: No company specified, redirecting to /company")
        return RedirectResponse(url="/company")
    
    # Validate company parameter
    valid_companies = ["MMM", "UML", "Both"]
    if company not in valid_companies:
        # print(f"DEBUG: Invalid company '{company}', redirecting to /company")
        return RedirectResponse(url="/company")
    
    # Update user's last company selection
    update_result = update_user_selection(username, company=company)
    # print(f"DEBUG: Company update result: {update_result}")
    
    # Show type selection page
    return templates.TemplateResponse(
        "type.html", 
        {
            "request": request, 
            "username": username,
            "company": company
        }
    )

@router.get("/save-type")
async def save_type(request: Request, type: str = None):
    """Save user's type selection and redirect to dashboard."""
    # Check session
    session_id = request.cookies.get("session_id")
    if not session_id:
        return RedirectResponse(url="/login")
    
    session = get_session(session_id)
    if not session:
        response = RedirectResponse(url="/login")
        response.delete_cookie("session_id")
        return response
    
    username = session["username"]
    # print(f"DEBUG: Save type - username: {username}, type param: {type}")
    
    # Validate type parameter
    valid_types = ["Mail", "Drive", "Both"]
    if not type or type not in valid_types:
        # print(f"DEBUG: Invalid type '{type}', redirecting to /company")
        return RedirectResponse(url="/company")
    
    # Update user's last type selection
    update_result = update_user_selection(username, type_selection=type)
    # print(f"DEBUG: Type update result: {update_result}")
    
    # Redirect to dashboard
    return RedirectResponse(url="/dashboard", status_code=303)

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, company: str = None):
    """Protected dashboard page with company and type context."""
    # Check session
    session_id = request.cookies.get("session_id")
    if not session_id:
        return RedirectResponse(url="/login")
    
    session = get_session(session_id)
    if not session:
        response = RedirectResponse(url="/login")
        response.delete_cookie("session_id")
        return response
    
    username = session["username"]
    # print(f"DEBUG: Dashboard - username: {username}")
    
    # Get user's stored selections
    selections = get_user_selections(username)
    stored_company = selections.get("last_company")
    stored_type = selections.get("last_type")
    
    # print(f"DEBUG: Retrieved selections - company: {stored_company}, type: {stored_type}")
    
    # If no stored selections, redirect to company selection
    if not stored_company:
        # print("DEBUG: No stored company, redirecting to /company")
        return RedirectResponse(url="/company")
    
    if not stored_type:
        print(f"DEBUG: No stored type, redirecting to /type?company={stored_company}")
        return RedirectResponse(url=f"/type?company={stored_company}")
    
    # Use template with user's stored selections
    return templates.TemplateResponse(
        "dashboard.html", 
        {
            "request": request, 
            "username": username,
            "company": stored_company,
            "type": stored_type
        }
    )

@router.get("/logout")
async def logout(request: Request):
    """Logout user by clearing session and cookies."""
    session_id = request.cookies.get("session_id")
    if session_id:
        delete_session(session_id)
    
    response = RedirectResponse(url="/login?message=You have been logged out successfully", status_code=303)
    response.delete_cookie("session_id")
    return response