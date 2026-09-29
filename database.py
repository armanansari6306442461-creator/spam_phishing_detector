import sqlite3

DATABASE = "phishguard.db"


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    conn = get_connection()

    # Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    """)

    # Scan history table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            status TEXT NOT NULL,
            risk REAL NOT NULL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


def create_user(username, password):
    

    conn = get_connection()

    try:

        conn.execute(
            """
            INSERT INTO users (username, password)
            VALUES (?, ?)
            """,
            (username, password)
        )

        conn.commit()

        return True

    except sqlite3.IntegrityError:

        return False

    finally:

        conn.close()


def get_user(username):

    conn = get_connection()

    user = conn.execute(
        """
        SELECT * FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    conn.close()

    return user


def save_scan(user_id, url, status, risk):

    conn = get_connection()

    conn.execute(
        """
        INSERT INTO scans
        (user_id, url, status, risk)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, url, status, risk)
    )

    conn.commit()
    conn.close()


def get_user_history(user_id):

    conn = get_connection()

    scans = conn.execute(
        """
        SELECT * FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,)
    ).fetchall()

    conn.close()

    return scans


def get_all_users():

    conn = get_connection()

    users = conn.execute(
        """
        SELECT id, username, is_admin
        FROM users
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return users


def get_all_scans():

    conn = get_connection()

    scans = conn.execute(
        """
        SELECT scans.*, users.username
        FROM scans
        LEFT JOIN users
        ON scans.user_id = users.id
        ORDER BY scans.id DESC
        """
    ).fetchall()

    conn.close()

    return scans


def get_statistics():

    conn = get_connection()

    total_users = conn.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    total_scans = conn.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]

    phishing_scans = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE status = 'PHISHING'"
    ).fetchone()[0]

    safe_scans = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE status = 'SAFE'"
    ).fetchone()[0]

    conn.close()

    return {
        "users": total_users,
        "scans": total_scans,
        "phishing": phishing_scans,
        "safe": safe_scans
    }
def get_scan_activity():
    conn = get_connection()

    activity = conn.execute("""
        SELECT
            DATE(scanned_at) AS scan_date,
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'PHISHING' THEN 1 ELSE 0 END) AS phishing,
            SUM(CASE WHEN status = 'SAFE' THEN 1 ELSE 0 END) AS safe
        FROM scans
        GROUP BY DATE(scanned_at)
        ORDER BY scan_date ASC
        LIMIT 7
    """).fetchall()

    conn.close()

    return activity
