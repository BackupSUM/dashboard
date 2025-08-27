from __future__ import print_function
import os.path
import re
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# --- Scopes ---
SCOPES = [
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/spreadsheets.readonly'
]

def authenticate():
    """Authenticate and return creds"""
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds

def list_drive_files(service):
    """List first 10 files in Drive"""
    results = service.files().list(
        pageSize=10, fields="files(id, name)"
    ).execute()
    items = results.get("files", [])
    print("\nYour Drive Files:")
    for f in items:
        print(f" - {f['name']} (ID: {f['id']})")

def read_sheet(service, sheet_url):
    """Read Google Sheet from link and display first rows"""
    # Extract Sheet ID from URL
    match = re.search(r"/d/([a-zA-Z0-9-_]+)", sheet_url)
    if not match:
        print("❌ Invalid sheet URL")
        return
    sheet_id = match.group(1)

    # Fetch values
    result = service.spreadsheets().values().get(
        spreadsheetId=sheet_id, range="A1:E10"
    ).execute()
    values = result.get("values", [])

    print("\nSheet Preview (first 10 rows):")
    for row in values:
        print(row)

def main():
    creds = authenticate()

    # Build services
    drive_service = build("drive", "v3", credentials=creds)
    sheets_service = build("sheets", "v4", credentials=creds)

    # 1. List Drive files
    list_drive_files(drive_service)

    # 2. Ask user for Sheet link
    sheet_link = input("\nPaste your Google Sheet link: ")
    read_sheet(sheets_service, sheet_link)

if __name__ == "__main__":
    main()
