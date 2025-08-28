import gspread
from google.oauth2.credentials import Credentials
from google.oauth2.service_account import Credentials as ServiceCredentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
import pandas as pd
from typing import List, Dict, Any, Optional
import re
import os
import json
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TempDatabase:
    def __init__(self, credentials_file: str = "DB\credentials.json", token_file: str = "token.json"):
        """Initialize the Google Sheets database connection."""
        self.credentials_file = credentials_file
        self.token_file = token_file
        self.gc = None
        self.scopes = [
            'https://www.googleapis.com/auth/spreadsheets',  # Full spreadsheets access (not just readonly)
            'https://www.googleapis.com/auth/drive.readonly'
        ]
        self._initialize_connection()
        
        # Define spreadsheet URLs based on company and type
        self.spreadsheet_urls = {
            "UML": {
                "Drive": [
                    "https://docs.google.com/spreadsheets/d/1FOSjviNv3EXY6KRJmw8Gez1dphafllC9qkr2k3nxMZI/edit?usp=drive_link",
                    "https://docs.google.com/spreadsheets/d/1y6Zgx3YgzpRNMOcrLxYQFNDxbcEWEEwVhvU3lxQVRoc/edit?usp=drive_link"
                ],
                "Mail": [
                    "https://docs.google.com/spreadsheets/d/1JICli6_KcY0YvawMXnqwR5GyusczOsfsNaVx9vb7rrM/edit?usp=drive_link",
                    "https://docs.google.com/spreadsheets/d/1BGu5LFmTRQ2tVUNyDD_Rk9cS064l5l_raL156E8-zYU/edit?usp=drive_link",
                    "https://docs.google.com/spreadsheets/d/1jGzZHWaGo_biEE88yMoYYlpenX0XubNTqy7SE0PkyHM/edit?usp=drive_link"
                ]
            },
            "MMM": {
                "Drive": [
                    "https://docs.google.com/spreadsheets/d/1OkRNm-7hVJuMPw2jAtjGDhIhkTA9mD0MnCdF2hMYYQk/edit?usp=drive_link",
                    "https://docs.google.com/spreadsheets/d/1veALtiZ6JN_C9hi8F0VlSYeRjwRmoaYC75QBm5gIdSU/edit?usp=drive_link"
                ],
                "Mail": [
                    "https://docs.google.com/spreadsheets/d/1g8QmjqtZxSz9p210fBfMQsFujpO0qi5Vv8x4yB5SQdw/edit?usp=drive_link",
                    "https://docs.google.com/spreadsheets/d/1HmMCVPak4DRKnTt0c26Dzmf53srS8euoLA3pnlWvX1w/edit?usp=drive_link"
                ]
            }
        }

    def _initialize_connection(self):
        """Initialize Google Sheets connection using OAuth2 or service account credentials."""
        try:
            creds = None
            
            # First, try OAuth2 flow (like your test script)
            if os.path.exists(self.token_file):
                logger.info("Found token.json, using OAuth2 credentials")
                creds = Credentials.from_authorized_user_file(self.token_file, self.scopes)
                
                # Refresh if expired
                if creds and creds.expired and creds.refresh_token:
                    logger.info("Refreshing expired OAuth2 token")
                    creds.refresh(Request())
                    # Save refreshed token
                    with open(self.token_file, 'w') as token:
                        token.write(creds.to_json())
                
                if creds and creds.valid:
                    self.gc = gspread.authorize(creds)
                    logger.info("Successfully connected using OAuth2 credentials")
                    return
            
            # If no token found, try to run OAuth flow with credentials.json
            if os.path.exists(self.credentials_file):
                # Check if it's OAuth2 client secrets or service account
                import json
                with open(self.credentials_file, 'r') as f:
                    cred_data = json.load(f)
                
                # Check if it's OAuth2 client secrets
                if 'installed' in cred_data or 'web' in cred_data:
                    logger.info("Found OAuth2 client secrets, running OAuth2 flow")
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_file, self.scopes
                    )
                    creds = flow.run_local_server(port=0)
                    
                    # Save the token for future use
                    with open(self.token_file, 'w') as token:
                        token.write(creds.to_json())
                    
                    self.gc = gspread.authorize(creds)
                    logger.info("Successfully connected using new OAuth2 token")
                    return
                
                # Check if it's service account
                elif 'client_email' in cred_data and 'private_key' in cred_data:
                    logger.info("Found service account credentials")
                    scope = [
                        "https://spreadsheets.google.com/feeds",
                        "https://www.googleapis.com/auth/drive"
                    ]
                    
                    creds = ServiceCredentials.from_service_account_file(
                        self.credentials_file, 
                        scopes=scope
                    )
                    
                    self.gc = gspread.authorize(creds)
                    logger.info("Successfully connected using service account credentials")
                    return
                else:
                    logger.error("Unknown credentials format")
                    raise ValueError("Credentials file format not recognized")
            
            raise FileNotFoundError("No valid credentials found. Please provide credentials.json or token.json")
            
        except Exception as e:
            logger.error(f"Failed to initialize Google Sheets connection: {e}")
            raise

    def _extract_spreadsheet_id(self, url: str) -> str:
        """Extract spreadsheet ID from Google Sheets URL."""
        match = re.search(r'/spreadsheets/d/([a-zA-Z0-9-_]+)', url)
        if match:
            return match.group(1)
        raise ValueError(f"Invalid Google Sheets URL: {url}")

    def get_active_spreadsheets(self, company: str, type_selection: str) -> List[str]:
        """Get list of active spreadsheet URLs based on company and type selection."""
        active_urls = []
        
        # Handle "Both" company selection
        companies_to_search = ["MMM", "UML"] if company == "Both" else [company]
        
        for comp in companies_to_search:
            if comp not in self.spreadsheet_urls:
                logger.warning(f"Company '{comp}' not found in configuration")
                continue

            company_data = self.spreadsheet_urls[comp]

            if type_selection == "Both":
                # Include both Drive and Mail
                active_urls.extend(company_data.get("Drive", []))
                active_urls.extend(company_data.get("Mail", []))
            elif type_selection in company_data:
                active_urls.extend(company_data[type_selection])
            else:
                logger.warning(f"Type '{type_selection}' not found for company '{comp}'")

        logger.info(f"Active spreadsheets for {company} - {type_selection}: {len(active_urls)} sheets")
        return active_urls

    def _read_spreadsheet_data(self, url: str) -> List[Dict[str, Any]]:
        """Read data from a single Google Spreadsheet."""
        try:
            spreadsheet_id = self._extract_spreadsheet_id(url)
            spreadsheet = self.gc.open_by_key(spreadsheet_id)
            
            # Get the first worksheet
            worksheet = spreadsheet.get_worksheet(0)
            
            # Get all records as list of dictionaries
            records = worksheet.get_all_records()
            
            # Add metadata to each record
            for record in records:
                record['_source_url'] = url
                record['_spreadsheet_id'] = spreadsheet_id
                record['_sheet_title'] = worksheet.title
                record['_source_name'] = spreadsheet.title
            
            logger.info(f"Successfully read {len(records)} records from {spreadsheet.title}")
            return records
            
        except Exception as e:
            logger.error(f"Error reading spreadsheet {url}: {e}")
            return []

    def search_records(self, company: str, type_selection: str, search_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search records across active spreadsheets."""
        all_results = []
        
        active_urls = self.get_active_spreadsheets(company, type_selection)
        
        for url in active_urls:
            try:
                records = self._read_spreadsheet_data(url)
                filtered_records = self._filter_records(records, search_params)
                all_results.extend(filtered_records)
            except Exception as e:
                logger.error(f"Error processing spreadsheet {url}: {e}")
                continue
        
        # Sort results by relevance if query exists
        if search_params.get('query'):
            all_results = self._sort_by_relevance(all_results, search_params['query'])
        
        logger.info(f"Search completed. Found {len(all_results)} matching records")
        return all_results

    def _filter_records(self, records: List[Dict[str, Any]], search_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Filter records based on search parameters."""
        if not records:
            return []
        
        filtered = records.copy()
        
        # General query search (searches across all text fields)
        query = search_params.get('query', '').strip().lower()
        if query:
            filtered = [
                record for record in filtered
                if self._matches_query(record, query)
            ]
        
        # Date filters
        date_filter = search_params.get('date')
        if date_filter:
            filtered = [
                record for record in filtered
                if self._matches_date_field(record, ['DOS', 'Date of Service', 'Date'], date_filter)
            ]
        
        dob_filter = search_params.get('dob')
        if dob_filter:
            filtered = [
                record for record in filtered
                if self._matches_date_field(record, ['DOB', 'Date of Birth'], dob_filter)
            ]
        
        # Category filter
        category = search_params.get('category', '').strip()
        if category:
            filtered = [
                record for record in filtered
                if self._matches_field(record, ['Category'], category)
            ]
        
        # Account filter
        account = search_params.get('account', '').strip()
        if account:
            filtered = [
                record for record in filtered
                if self._matches_field(record, ['Account', 'Email'], account)
            ]
        
        # Company filter
        company_filter = search_params.get('company', '').strip()
        if company_filter:
            filtered = [
                record for record in filtered
                if self._matches_field(record, ['Company'], company_filter)
            ]
        
        return filtered

    def _matches_query(self, record: Dict[str, Any], query: str) -> bool:
        """Check if record matches the general search query."""
        # Convert all record values to strings and search
        record_text = ' '.join(str(value).lower() for value in record.values() 
                              if value and not str(value).startswith('_'))
        return query in record_text

    def _matches_field(self, record: Dict[str, Any], field_names: List[str], value: str) -> bool:
        """Check if record field matches the given value (case-insensitive)."""
        search_value = value.lower().strip()
        
        for field_name in field_names:
            # Try exact match and variations
            possible_names = [field_name, field_name.lower(), field_name.upper(), field_name.title()]
            
            for name in possible_names:
                if name in record and record[name]:
                    record_value = str(record[name]).lower().strip()
                    if search_value in record_value:
                        return True
        
        return False

    def _matches_date_field(self, record: Dict[str, Any], field_names: List[str], target_date: str) -> bool:
        """Check if record date field matches the target date."""
        for field_name in field_names:
            possible_names = [field_name, field_name.lower(), field_name.upper(), field_name.title()]
            
            for name in possible_names:
                if name in record and record[name]:
                    try:
                        record_date = str(record[name]).strip()
                        if record_date == target_date:
                            return True
                        # Try to match partial dates (YYYY-MM-DD format)
                        if target_date in record_date or record_date in target_date:
                            return True
                    except:
                        continue
        
        return False

    def _sort_by_relevance(self, records: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
        """Sort records by relevance to the search query."""
        def relevance_score(record):
            score = 0
            query_lower = query.lower()
            
            # Check key fields with higher weights
            important_fields = ['Name', 'Filename', 'Email', 'Company']
            for field in important_fields:
                for possible_name in [field, field.lower(), field.upper(), field.title()]:
                    if possible_name in record and record[possible_name]:
                        field_value = str(record[possible_name]).lower()
                        if query_lower in field_value:
                            score += 10
                            if field_value.startswith(query_lower):
                                score += 5
                        break
            
            # Check all other fields with lower weight
            for key, value in record.items():
                if not key.startswith('_') and isinstance(value, str) and query_lower in value.lower():
                    score += 1
            
            return score
        
        return sorted(records, key=relevance_score, reverse=True)

    def get_download_info(self, record: Dict[str, Any]) -> Dict[str, str]:
        """Extract download/view information from a record."""
        info = {
            'view_url': '',
            'download_url': '',
            'filename': ''
        }
        
        # Try to find drive link or file URL
        possible_link_fields = [
            'Drive Link', 'DriveLink', 'Link', 'URL', 'File Link', 'Drive URL',
            'File', 'Document', 'Attachment Link', 'ATTACHMENT LINK'
        ]
        for field in possible_link_fields:
            for possible_name in [field, field.lower(), field.upper(), field.title()]:
                if possible_name in record and record[possible_name]:
                    url = str(record[possible_name]).strip()
                    if url and url.startswith('http'):
                        info['view_url'] = url
                        # Convert to download URL if it's a Google Drive link
                        if 'drive.google.com' in url:
                            info['download_url'] = self._convert_to_download_url(url)
                        else:
                            info['download_url'] = url
                        break
            if info['view_url']:
                break
        
        # Try to find filename
        possible_filename_fields = [
            'Filename', 'FILENAME', 'File Name', 'FILE NAME', 'Name', 'NAME',
            'Title', 'Document Name', 'Attachment Filename', 'ATTACHMENT FILENAME'
        ]
        for field in possible_filename_fields:
            for possible_name in [field, field.lower(), field.upper(), field.title()]:
                if possible_name in record and record[possible_name]:
                    info['filename'] = str(record[possible_name]).strip()
                    break
            if info['filename']:
                break
        # Derive filename from link if still empty
        if not info['filename'] and info['view_url']:
            try:
                import urllib.parse
                path = urllib.parse.urlparse(info['view_url']).path
                last = path.rstrip('/').split('/')[-1]
                info['filename'] = last or ''
            except Exception:
                pass
        
        return info

    def get_unique_values(self, company: str, type_selection: str) -> Dict[str, list]:
        """Collect unique filter values (companies, accounts, categories) across active sheets.

        - companies: values from 'Company' column
        - accounts: values from 'Account' or 'Email' column
        - categories: values from 'Category' column
        """
        companies = set()
        accounts = set()
        categories = set()

        active_urls = self.get_active_spreadsheets(company, type_selection)
        for url in active_urls:
            try:
                records = self._read_spreadsheet_data(url)
                for rec in records:
                    # Company
                    for key in ['Company', 'company', 'COMPANY']:
                        if key in rec and rec[key]:
                            companies.add(str(rec[key]).strip())
                            break
                    # Account/Email
                    for key in ['Account', 'Email', 'account', 'email', 'ACCOUNT']:
                        if key in rec and rec[key]:
                            accounts.add(str(rec[key]).strip())
                            break
                    # Category
                    for key in ['Category', 'category', 'CATEGORY']:
                        if key in rec and rec[key]:
                            categories.add(str(rec[key]).strip())
                            break
            except Exception as e:
                logger.error(f"Error collecting unique values from {url}: {e}")
                continue

        def _sorted_unique(values: set) -> list:
            try:
                return sorted(values, key=lambda s: str(s).lower())
            except Exception:
                return sorted(list(values))

        return {
            'companies': _sorted_unique(companies),
            'accounts': _sorted_unique(accounts),
            'categories': _sorted_unique(categories),
        }

    def _convert_to_download_url(self, view_url: str) -> str:
        """Convert Google Drive view URL to download URL."""
        try:
            # Extract file ID from Google Drive URL
            file_id_match = re.search(r'/d/([a-zA-Z0-9-_]+)', view_url)
            if file_id_match:
                file_id = file_id_match.group(1)
                return f"https://drive.google.com/uc?export=download&id={file_id}"
        except:
            pass
        return view_url

    def export_results(self, records: List[Dict[str, Any]], export_format: str = 'csv') -> bytes:
        """Export search results to specified format."""
        if not records:
            return b""
        
        # Create DataFrame and clean data
        df = pd.DataFrame(records)
        
        # Remove internal metadata columns
        metadata_cols = [col for col in df.columns if col.startswith('_')]
        df = df.drop(columns=metadata_cols, errors='ignore')
        
        fmt = export_format.lower()
        if fmt == 'csv':
            return df.to_csv(index=False).encode('utf-8')
        elif fmt in ('excel', 'xlsx'):
            from io import BytesIO
            buffer = BytesIO()
            df.to_excel(buffer, index=False, engine='openpyxl')
            return buffer.getvalue()
        elif fmt == 'pdf':
            try:
                from io import BytesIO
                from reportlab.lib import colors
                from reportlab.lib.pagesizes import A4, landscape
                from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
                from reportlab.lib.styles import getSampleStyleSheet
                from reportlab.platypus import Paragraph
                from reportlab.lib import utils
            except Exception as e:
                raise ValueError("PDF export requires 'reportlab' to be installed")

            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), leftMargin=18, rightMargin=18, topMargin=18, bottomMargin=18)
            data = [list(df.columns)] + df.astype(str).values.tolist()
            # Truncate very long cell text to keep table readable in PDF
            max_len = 120
            for r in range(1, len(data)):
                data[r] = [ (c if len(c) <= max_len else c[:max_len-1] + '…') for c in data[r] ]
            table = Table(data, repeatRows=1)
            style = TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f0f0f0')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.black),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 9),
                ('FONTSIZE', (0,1), (-1,-1), 8),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fafafa')])
            ])
            table.setStyle(style)
            doc.build([table])
            return buffer.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {export_format}")

# Global database instance
_db_instance = None

def get_database() -> TempDatabase:
    """Get singleton database instance."""
    global _db_instance
    if _db_instance is None:
        try:
            _db_instance = TempDatabase()
        except Exception as e:
            logger.error(f"Failed to create database instance: {e}")
            raise
    return _db_instance

def test_connection():
    """Test function to verify connection works."""
    try:
        # Clear any existing token with wrong scopes
        token_file = "token.json"
        if os.path.exists(token_file):
            print("Clearing existing token due to scope changes...")
            os.remove(token_file)
        
        db = TempDatabase()
        logger.info("Database connection test successful")
        
        # Test with UML Drive sheets
        active_urls = db.get_active_spreadsheets("UML", "Drive")
        logger.info(f"Found {len(active_urls)} active spreadsheets for UML Drive")
        
        if active_urls:
            # Try to read first sheet
            test_data = db._read_spreadsheet_data(active_urls[0])
            logger.info(f"Successfully read {len(test_data)} records from test sheet")
            
            if test_data:
                logger.info(f"Sample record fields: {list(test_data[0].keys())}")
                print(f"\n✅ SUCCESS! Found {len(test_data)} records in test sheet")
                print(f"📋 Available fields: {', '.join([f for f in test_data[0].keys() if not f.startswith('_')])}")
            else:
                print("⚠️  Sheet is empty or no data found")
        else:
            print("⚠️  No active spreadsheets found for UML Drive")
        
        return True
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        print(f"❌ Connection failed: {e}")
        return False

# Test the connection if run directly
if __name__ == "__main__":
    print("Testing database connection...")
    success = test_connection()
    print(f"Connection test: {'SUCCESS' if success else 'FAILED'}")
