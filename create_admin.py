from werkzeug.security import generate_password_hash
from database import get_connection


username = "Engg_Arman"
password = "Arman123"


conn = get_connection()

conn.execute(
    """
    INSERT OR IGNORE INTO users
    (username, password, is_admin)
    VALUES (?, ?, ?)
    """,
    (
        username,
        generate_password_hash(password),
        1
    )
)

conn.commit()
conn.close()

print("Admin account created!")
print("Username:", username)
print("Password:", password)