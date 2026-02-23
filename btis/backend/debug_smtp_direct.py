import smtplib
import os
from dotenv import load_dotenv

# Force reload of .env
load_dotenv(override=True)

user = os.getenv('MAIL_USERNAME', '').strip()
raw_pass = os.getenv('MAIL_PASSWORD', '')
clean_pass = raw_pass.replace(' ', '').strip()

print(f"DEBUG DIAGNOSTICS:")
print(f"User: '{user}'")
print(f"Pass Raw: '{raw_pass}' (Len: {len(raw_pass)})")
print(f"Pass Clean: '{clean_pass}' (Len: {len(clean_pass)})")

# Check for invisible characters
print("Pass Chars:", [ord(c) for c in clean_pass])

try:
    print("Connecting to smtp.gmail.com:587...")
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.ehlo()
    server.starttls()
    server.ehlo()
    print("Logging in...")
    server.login(user, clean_pass)
    print("SUCCESS! Login accepted.")
    server.quit()
except Exception as e:
    print(f"FAIL: {e}")
