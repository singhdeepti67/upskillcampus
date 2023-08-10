import bcrypt
import mysql.connector
import re

# Connect to the MySQL database
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="new_database"
)

cursor = db.cursor()


# Create the table if it doesn't exist
cursor.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL
    )
""")

# Function to hash and salt a password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Function to verify a password against a hashed password
def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Function to generate a strong password
def generate_strong_password(password):
   # Check if the password is at least 8 characters long
    if len(password) < 8:
        return False

    # Check if the password contains at least one uppercase letter
    if not re.search(r"[A-Z]", password):
        return False

    # Check if the password contains at least one lowercase letter
    if not re.search(r"[a-z]", password):
        return False

    # Check if the password contains at least one digit
    if not re.search(r"\d", password):
        return False

    # Check if the password contains at least one special character
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False

    # If all criteria are met, the password is considered strong
    return True

# Function to store a password in the database
def store_password(username, password):
    cursor = db.cursor()
    hashed_password = hash_password(password)
    query = "INSERT INTO passwords (username, password) VALUES (%s, %s)"
    values = (username, hashed_password)
    cursor.execute(query, values)
    db.commit()
    cursor.close()

# Function to retrieve a password from the database
def retrieve_password(username):
    cursor = db.cursor()
    query = "SELECT password FROM passwords WHERE username = %s"
    value = (username,)
    cursor.execute(query, value)
    result = cursor.fetchone()
    cursor.close()
    if result:
        return result[0]
    else:
        return None

# User Interface
def user_interface():
    print("1. Store a password")
    print("2. Retrieve a password")
    choice = input("Enter your choice: ")
    
    if choice == "1":
        username = input("Enter username: ")
        password = input("Enter password: ")
        if generate_strong_password(password):
            store_password(username, password)
            print("Password is strong and hence stored successfully.")
        else:
            print("Password is not strong enter another password.")
            user_interface()
        
    elif choice == "2":
        username = input("Enter username: ")
        hashed_password = retrieve_password(username)
        
        if hashed_password:
            password = input("Enter password: ")
            
            if verify_password(password, hashed_password):
                print("Password verification successful!")
            else:
                print("Invalid password!")
        else:
            print("Username not found!")
        
    else:
        print("Invalid choice!")

db.commit()
cursor.close()
# Call the user interface function
user_interface()

# Close the database connection
db.close()
