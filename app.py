from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)

from werkzeug.security import generate_password_hash, check_password_hash

from detector import detect_phishing


from database import (
    init_db,
    create_user,
    get_user,
    save_scan,
    get_user_history,
    get_all_users,
    get_all_scans,
    get_statistics,
    get_scan_activity
)


app = Flask(__name__, static_folder="templates/static")

# Session security key
app.secret_key = "change-this-secret-key"

# Create database
init_db()


# =========================
# HOME / LOGIN
# =========================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("scanner"))

    return redirect(url_for("login"))


# =========================
# REGISTER
# =========================

@app.route("/register", methods=["GET", "POST"])
def register():

    message = None

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:

            message = "Please fill all fields."

        else:

            hashed_password = generate_password_hash(password)

            success = create_user(
                username,
                hashed_password
            )

            if success:

                return redirect(url_for("login"))

            else:

                message = "Username already exists."

    return render_template(
        "register.html",
        message=message
    )


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():

    message = None

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user(username)

        if user and check_password_hash(
            user["password"],
            password
        ):

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = user["is_admin"]

            if user["is_admin"] == 1:
                return redirect(url_for("admin"))

            return redirect(url_for("scanner"))

        message = "Invalid username or password."

    return render_template(
        "login.html",
        message=message
    )


# =========================
# LOGOUT
# =========================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================
# SCANNER
# =========================

@app.route("/scanner", methods=["GET", "POST"])
def scanner():

    if "user_id" not in session:

        return redirect(url_for("login"))

    result = None
    url = ""

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url:

            result = detect_phishing(url)

            save_scan(
                session["user_id"],
                url,
                result["status"],
                result["risk"]
            )

    return render_template(
        "index.html",
        result=result,
        url=url,
        username=session["username"]
    )


# =========================
# HISTORY
# =========================

@app.route("/history")
def history():

    if "user_id" not in session:

        return redirect(url_for("login"))

    scans = get_user_history(
        session["user_id"]
    )

    return render_template(
        "history.html",
        scans=scans,
        username=session["username"]
    )


# =========================
# ADMIN DASHBOARD
# =========================

@app.route("/admin")
def admin():

    if "user_id" not in session:

        return redirect(url_for("login"))

    if session.get("is_admin") != 1:

        return "Access Denied", 403

    statistics = get_statistics()

    users = get_all_users()

    scans = get_all_scans()
    scan_activity = get_scan_activity()

    return render_template(
        "admin.html",
        statistics=statistics,
        users=users,
        scans=scans,
        scan_activity=scan_activity
    )


# =========================
# RUN APP
# =========================

if __name__ == "__main__":

    app.run(debug=True)