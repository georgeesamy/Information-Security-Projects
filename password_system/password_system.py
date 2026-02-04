import re  
from zxcvbn import zxcvbn
import re, os, time, hmac, hashlib, secrets, string, random
import bcrypt

from datetime import datetime
users={}
BAD_WORDS = [
    "password", "admin", "qwerty", "welcome", "abc", "abcd", "iloveyou",
    "user", "letmein", "football", "login", "mon2key", "dragon", "master",
    "hello", "sunshine", "princess", "azerty", "qwertyuiop"]

def check_password(password):
    tips = []  

    if len(password) < 8:
        tips.append("Use at least 8characters.")
    if not re.search("[A-Z]", password):
        tips.append("Add uppercase letters (A-Z).")
    if not re.search("[a-z]", password):
        tips.append("Add lowercase letters (a-z).")
    if not re.search("[0-9]", password):
        tips.append("Add numbers (0-9).")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\",.<>/?\\|`~]", password):
        tips.append("Add at least one special symbol.")

    low = password.lower()
    for bad in BAD_WORDS:
        if bad in low:
            tips.append(f"Don't use common words like '{bad}'.")
            break 
    if re.search(r"1234|abcd|1111|0000", password):
        tips.append("Avoid easy patterns like 1234 or abcd.")


    if len(tips) == 0:
        result = zxcvbn(password)
        score = result["score"]
        feedback = result["feedback"]

        print(f"\nScore: {score} (0 = very weak, 4 = very strong)")

        if feedback["warning"]:
            print("Warning:", feedback["warning"])
        if feedback["suggestions"]:
            print("Suggestions:")
            for s in feedback["suggestions"]:
                print("-", s)

        if score >= 3:
            print("\n Password is strong.")
        else:
            print("\n Password is fair but can be improved.")
    else:
        print("\n Weak password.")
        print("Tips to improve:")
        for t in tips[:3]:
            print("-", t)






def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password, stored_hash):
    return bcrypt.checkpw(password.encode(), stored_hash)

def meets_policy(password):
    """Check if password is strong enough."""
    return len(password) >= 8 and zxcvbn(password)["score"] >= 3

def sign_up():
    print("\n SIGN UP")
    username = input("Enter username: ").strip()
    
    if username in users:
        print("Username already exists.")
        return False
    
    while True:
        password = input("Enter password: ")
        check_password(password)
        if meets_policy(password):
            break
        print("Password is too weak, try again.")
    
    pw_hash = hash_password(password)
    users[username] = {
        'password_hash': pw_hash,
        'created_date': datetime.now(),
        'last_login': None,
        'login_count': 0,
        'failed_attempts': 0
    }
    print("Account created successfully.")
    return True

def login():
    print("\nLOGIN")
    username = input("Enter username: ").strip()
    
    if username not in users:
        print("User not found.")
        return False
    
    if users[username].get('failed_attempts', 0) >= 3:
        print("Account is locked due to too many failed attempts.")
        return False
    
    password = input("Enter password: ")
    
    if not verify_password(password, users[username]['password_hash']):
        users[username]['failed_attempts'] = users[username].get('failed_attempts', 0) + 1
        print("Invalid password")
        return False
    
    users[username]['failed_attempts'] = 0
    
    if users[username]['login_count'] >= 3:
        print("Password expired after 3 logins. You must change it now.")
        while True:
            new_password = input("Enter new password: ")
            check_password(new_password)
            if meets_policy(new_password):
                users[username]['password_hash'] = hash_password(new_password)
                users[username]['login_count'] = 0
                print("Password changed. Login successful")
                break
            print("Password is too weak. Try again.")
    else:
        users[username]['login_count'] += 1
        print("Login successful")
    
    users[username]['last_login'] = datetime.now()
    return True

def generate_password():
    while True:
        password = [
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice(string.digits),
            random.choice(string.punctuation)
        ]
        chars = string.ascii_letters + string.digits + string.punctuation
        password += [random.choice(chars) for _ in range(8)]
        random.shuffle(password)
        password = ''.join(password)
        
        if meets_policy(password):
            return password

def change_password():
    print("\n CHANGE PASSWORD")
    username = input("Enter username: ").strip()
    
    if username not in users:
        print("User not found.")
        return False
    
    old_password = input("Enter old password: ")
    
    if not verify_password(old_password, users[username]['password_hash']):
        print("Invalid old password")
        return False
    
    while True:
        new_password = input("Enter new password: ")
        check_password(new_password)
        if meets_policy(new_password):
            break
        print("Password is too weak,Try again.")
    
    users[username]['password_hash'] = hash_password(new_password)
    users[username]['login_count'] = 0
    users[username]['failed_attempts'] = 0
    print("Password changed successfully.")
    return True

def main():
    while True:
        print("\nPASSWORD MANAGER")
        print("1. Sign Up")
        print("2. Login")
        print("3. Change Password")
        print("4. Generate Password")
        print("5. Exit")
        
        choice = input("Choose option: ").strip()
        
        if choice == '1':
            sign_up()
        elif choice == '2':
            login()
        elif choice == '3':
            change_password()
        elif choice == '4':
            pwd = generate_password()
            print(f"Generated password: {pwd}")
        elif choice == '5':
            break
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()