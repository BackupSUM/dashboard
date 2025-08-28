from fastapi import APIRouter, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from datetime import timedelta
import re
import json
import io
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
    ACCESS_TOKEN_EXPIRE_MINUTES,
    SESSION_EXPIRE_DAYS
)

# Import database
try:
    from DB.temp_db import get_database
    database_available = True
except ImportError:
    database_available = False
    print("Warning: Database module not available. Search functionality will be disabled.")

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

def get_current_user_session(request: Request):
    """Get current user session or return None."""
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None
    
    session = get_session(session_id)
    if not session:
        return None
    
    return session

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
        max_age=SESSION_EXPIRE_DAYS * 24 * 60 * 60,
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
    print(f"DEBUG: Type page - username: {username}, company param: {company}")
    
    # If no company specified, redirect to company selection
    if not company:
        print("DEBUG: No company specified, redirecting to /company")
        return RedirectResponse(url="/company")
    
    # Validate company parameter
    valid_companies = ["MMM", "UML", "Both"]
    if company not in valid_companies:
        print(f"DEBUG: Invalid company '{company}', redirecting to /company")
        return RedirectResponse(url="/company")
    
    # Update user's last company selection
    update_result = update_user_selection(username, company=company)
    print(f"DEBUG: Company update result: {update_result}")
    
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
    print(f"DEBUG: Save type - username: {username}, type param: {type}")
    
    # Validate type parameter
    valid_types = ["Mail", "Drive", "Both"]
    if not type or type not in valid_types:
        print(f"DEBUG: Invalid type '{type}', redirecting to /company")
        return RedirectResponse(url="/company")
    
    # Update user's last type selection
    update_result = update_user_selection(username, type_selection=type)
    print(f"DEBUG: Type update result: {update_result}")
    
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
    print(f"DEBUG: Dashboard - username: {username}")
    
    # Get user's stored selections
    selections = get_user_selections(username)
    stored_company = selections.get("last_company")
    stored_type = selections.get("last_type")
    
    print(f"DEBUG: Retrieved selections - company: {stored_company}, type: {stored_type}")
    
    # If no stored selections, redirect to company selection
    if not stored_company:
        print("DEBUG: No stored company, redirecting to /company")
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
            "type": stored_type,
            "database_available": database_available
        }
    )

# Search API Endpoints
@router.post("/api/search")
async def search_records(
    request: Request,
    query: str = Form(""),
    date: str = Form(""),
    dob: str = Form(""),
    company: str = Form(""),
    category: str = Form(""),
    account: str = Form("")
):
    """Search records based on user's company and type selections."""
    
    # Check if database is available
    if not database_available:
        return JSONResponse(
            status_code=503,
            content={
                'success': False,
                'error': 'Database service unavailable',
                'message': 'Search functionality is currently disabled'
            }
        )
    
    # Check authentication
    session = get_current_user_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = session["username"]
    
    # Get user's stored selections
    user_selections = get_user_selections(username)
    user_company = user_selections.get("last_company")
    user_type = user_selections.get("last_type")
    
    if not user_company or not user_type:
        return JSONResponse(
            status_code=400,
            content={
                'success': False,
                'error': 'Incomplete profile',
                'message': 'Please complete your company and type selection first'
            }
        )
    
    # Prepare search parameters
    search_params = {
        'query': query.strip(),
        'date': date.strip() if date else '',
        'dob': dob.strip() if dob else '',
        'company': company.strip() if company else '',
        'category': category.strip() if category else '',
        'account': account.strip() if account else ''
    }
    
    try:
        # Get database instance and perform search
        db = get_database()
        results = db.search_records(user_company, user_type, search_params)
        
        # Helpers to read values with flexible column names
        def first_val(rec, keys, default=""):
            for k in keys:
                if k in rec and rec[k] not in (None, ""):
                    return str(rec[k])
            return default

        def should_exclude_file(name: str, link: str) -> bool:
            """Return True if filename or link indicates a .json/.html/.htm file."""
            try:
                nm = (name or "").strip().lower()
                if nm.endswith(('.json', '.html', '.htm')):
                    return True
                lk = (link or "").strip().lower()
                if not lk:
                    return False
                # Strip query params and fragments
                base = lk.split('?', 1)[0].split('#', 1)[0]
                if base.endswith(('.json', '.html', '.htm')):
                    return True
            except Exception:
                pass
            return False

        # Format results for frontend
        formatted_results = []
        for record in results:
            download_info = db.get_download_info(record)
            
            account = first_val(record, ['Account','ACCOUNT','Email','EMAIL'])
            filename = download_info.get('filename') or first_val(record, ['Filename','FILENAME','File Name','FILE NAME','Attachment Filename','ATTACHMENT FILENAME'])
            name = first_val(record, ['Name','NAME'])
            dos = first_val(record, ['DOS','Date of Service','DOS/ DATE','DOS/DATE','DOS / DATE','Date','DATE'])
            dob = first_val(record, ['DOB','Date of Birth','DATE OF BIRTH'])
            email = first_val(record, ['Email','EMAIL'])
            company_val = first_val(record, ['Company','COMPANY'])
            category = first_val(record, ['Category','CATEGORY'])
            reason = first_val(record, ['Reason','REASON','Body','BODY','Status','STATUS'])

            formatted_record = {
                'account': account,
                'filename': filename,
                'drive_link': download_info.get('view_url', ''),
                'name': name,
                'dos': dos,
                'dob': dob,
                'email': email,
                'company': company_val,
                'category': category,
                'reason': reason,
                'view_url': download_info.get('view_url', ''),
                'download_url': download_info.get('download_url', ''),
                'source_sheet': record.get('_source_name', ''),
                'raw_record': record
            }
            # Skip unwanted file types (.json/.html/.htm)
            if should_exclude_file(formatted_record['filename'], formatted_record['view_url']):
                continue
            formatted_results.append(formatted_record)
        
        return JSONResponse(content={
            'success': True,
            'results': formatted_results,
            'total_count': len(formatted_results),
            'search_params': search_params,
            'user_selections': {
                'company': user_company,
                'type': user_type
            }
        })
        
    except Exception as e:
        print(f"Search error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                'success': False,
                'error': str(e),
                'message': 'An error occurred while searching records'
            }
        )

@router.get("/api/filter-options")
async def get_filter_options(request: Request):
    """Return unique filter options (accounts, companies, categories) for current selection."""
    # Check if database is available
    if not database_available:
        return JSONResponse(
            status_code=503,
            content={'success': False, 'message': 'Database service unavailable'}
        )

    # Check authentication
    session = get_current_user_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        username = session["username"]
        user_selections = get_user_selections(username)
        user_company = user_selections.get("last_company")
        user_type = user_selections.get("last_type")

        if not user_company or not user_type:
            return JSONResponse(content={
                'success': False,
                'message': 'Please complete company and type selection first'
            })

        db = get_database()
        uniques = db.get_unique_values(user_company, user_type)

        return JSONResponse(content={
            'success': True,
            'options': uniques,
            'user_selections': {
                'company': user_company,
                'type': user_type
            }
        })
    except Exception as e:
        print(f"Filter options error: {e}")
        return JSONResponse(
            status_code=500,
            content={'success': False, 'message': f'Failed to load filter options: {str(e)}'}
        )

@router.post("/api/export")
async def export_search_results(
    request: Request,
    format: str = Form("csv"),
    search_data: str = Form("")
):
    """Export search results to specified format."""
    
    # Check if database is available
    if not database_available:
        raise HTTPException(status_code=503, detail="Database service unavailable")
    
    # Check authentication
    session = get_current_user_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Parse search data from frontend
        if search_data:
            results_data = json.loads(search_data)
            results = results_data.get('results', [])
        else:
            results = []
        
        if not results:
            raise HTTPException(status_code=400, detail="No data to export")
        
        # Exclude unwanted file types from export (.json/.html/.htm)
        def should_exclude_file(name: str, link: str) -> bool:
            nm = (name or "").strip().lower()
            if nm.endswith(('.json', '.html', '.htm')):
                return True
            lk = (link or "").strip().lower()
            if lk:
                base = lk.split('?', 1)[0].split('#', 1)[0]
                if base.endswith(('.json', '.html', '.htm')):
                    return True
            return False

        filtered_results = []
        for r in results:
            if not should_exclude_file(r.get('filename', ''), r.get('view_url', '')):
                filtered_results.append(r)

        # Convert back to record format for export
        records_for_export = []
        for result in filtered_results:
            if 'raw_record' in result:
                record = result['raw_record'].copy()
                # Remove internal fields
                for key in list(record.keys()):
                    if key.startswith('_'):
                        del record[key]
                records_for_export.append(record)
            else:
                # Fallback: create record from formatted data
                records_for_export.append({
                    'Account': result.get('account', ''),
                    'Filename': result.get('filename', ''),
                    'Drive Link': result.get('drive_link', ''),
                    'Name': result.get('name', ''),
                    'DOS': result.get('dos', ''),
                    'DOB': result.get('dob', ''),
                    'Email': result.get('email', ''),
                    'Company': result.get('company', ''),
                    'Category': result.get('category', ''),
                    'Reason': result.get('reason', '')
                })
        
        # Export data
        db = get_database()
        export_data = db.export_results(records_for_export, format)
        
        # Determine content type and filename
        username = session["username"]
        fmt = format.lower()
        if fmt == 'csv':
            content_type = "text/csv"
            filename = f"search_results_{username}.csv"
        elif fmt in ('excel', 'xlsx'):
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            filename = f"search_results_{username}.xlsx"
        elif fmt == 'pdf':
            content_type = "application/pdf"
            filename = f"search_results_{username}.pdf"
        else:
            raise HTTPException(status_code=400, detail="Unsupported export format")
        
        # Return file as streaming response
        return StreamingResponse(
            io.BytesIO(export_data),
            media_type=content_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid search data format")
    except Exception as e:
        print(f"Export error: {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

@router.get("/api/test-connection")
async def test_database_connection(request: Request):
    """Test database connection and return sample data."""
    
    # Check if database is available
    if not database_available:
        return JSONResponse(
            status_code=503,
            content={
                'success': False,
                'message': 'Database service unavailable'
            }
        )
    
    # Check authentication
    session = get_current_user_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        username = session["username"]
        user_selections = get_user_selections(username)
        user_company = user_selections.get("last_company")
        user_type = user_selections.get("last_type")
        
        if not user_company or not user_type:
            return JSONResponse(content={
                'success': False,
                'message': 'Please complete company and type selection first'
            })
        
        # Get database instance and test connection
        db = get_database()
        active_urls = db.get_active_spreadsheets(user_company, user_type)
        
        # Test with empty search to get sample data
        test_results = db.search_records(user_company, user_type, {'query': ''})
        
        return JSONResponse(content={
            'success': True,
            'user_selections': {
                'company': user_company,
                'type': user_type
            },
            'active_spreadsheets': len(active_urls),
            'total_records': len(test_results),
            'sample_fields': list(test_results[0].keys()) if test_results else [],
            'message': 'Database connection successful'
        })
        
    except Exception as e:
        print(f"Connection test error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                'success': False,
                'error': str(e),
                'message': 'Database connection test failed'
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
