
import os
import secrets
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "requests.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-before-deployment"
)

app.config.update(
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("FLASK_ENV") == "production"
        or os.environ.get("RENDER") == "true"
    ),
)

CATEGORIES = [
    "Broken Streetlight",
    "Water Supply Issue",
    "Garbage Collection",
    "Roads and Drainage",
    "Public Health and Sanitation",
    "Other Public Service Issue",
]

STATUSES = [
    "Pending",
    "In Progress",
    "Resolved",
    "Rejected",
]


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:

        # Users table
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'citizen',
                created_at TEXT NOT NULL
            )
        """)

        # Service requests table
        db.execute("""
            CREATE TABLE IF NOT EXISTS service_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reference TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                subject TEXT NOT NULL,
                description TEXT NOT NULL,
                location TEXT NOT NULL DEFAULT 'Not provided',
                image_filename TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Pending',
                admin_note TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # Upgrade older databases safely.
        columns = {
            row[1]
            for row in db.execute(
                "PRAGMA table_info(service_requests)"
            ).fetchall()
        }

        if "location" not in columns:
            db.execute("""
                ALTER TABLE service_requests
                ADD COLUMN location TEXT NOT NULL DEFAULT 'Not provided'
            """)

        if "image_filename" not in columns:
            db.execute("""
                ALTER TABLE service_requests
                ADD COLUMN image_filename TEXT DEFAULT ''
            """)

        # Optional administrator bootstrap using Render environment variables.
        admin_email = os.environ.get(
            "ADMIN_EMAIL", ""
        ).strip().lower()

        admin_password = os.environ.get("ADMIN_PASSWORD", "")

        if admin_email and admin_password:
            existing_admin = db.execute(
                "SELECT id, role FROM users WHERE LOWER(email) = ?",
                (admin_email,)
            ).fetchone()

            if existing_admin:
                # Promote the explicitly configured account to administrator.
                db.execute(
                    "UPDATE users SET role = 'admin' WHERE id = ?",
                    (existing_admin["id"],)
                )
            else:
                db.execute("""
                    INSERT INTO users
                    (full_name, email, password_hash, role, created_at)
                    VALUES (?, ?, ?, 'admin', ?)
                """, (
                    "PSB Administrator",
                    admin_email,
                    generate_password_hash(admin_password),
                    datetime.utcnow().isoformat(timespec="seconds")
                ))


# Initialize the database when the application starts.
init_db()


# --------------------------------------------------
# AUTHENTICATION DECORATORS
# --------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "info")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in as an administrator.", "info")
            return redirect(url_for("login"))

        if session.get("role") != "admin":
            abort(403)

        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def make_reference():
    return (
        "MPSB-"
        + datetime.utcnow().strftime("%y%m%d")
        + "-"
        + secrets.token_hex(3).upper()
    )


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# --------------------------------------------------
# CITIZEN REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not full_name or not email or len(password) < 8:
            flash(
                "Enter your name and email, and use a password "
                "with at least 8 characters.",
                "error"
            )
            return render_template("register.html")

        try:
            with get_db() as db:
                db.execute("""
                    INSERT INTO users
                    (full_name, email, password_hash, role, created_at)
                    VALUES (?, ?, ?, 'citizen', ?)
                """, (
                    full_name,
                    email,
                    generate_password_hash(password),
                    datetime.utcnow().isoformat(timespec="seconds")
                ))

            flash(
                "Account created. You can now sign in.",
                "success"
            )
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash(
                "An account with that email already exists.",
                "error"
            )

    return render_template("register.html")


# --------------------------------------------------
# ADMINISTRATOR REGISTRATION
# --------------------------------------------------

@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():

    # Prevent signed-in citizens from accessing registration.
    if session.get("user_id"):
        if session.get("role") == "admin":
            return redirect(url_for("admin_dashboard"))

        flash(
            "Sign out before accessing administrator registration.",
            "error"
        )
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        invite_code = request.form.get("invite_code", "")

        expected_code = os.environ.get(
            "ADMIN_REGISTRATION_CODE", ""
        )

        # Registration stays disabled until a code is configured.
        if not expected_code:
            flash(
                "Administrator registration is currently disabled.",
                "error"
            )
            return render_template("admin_register.html")

        # Verify the invitation code.
        if not secrets.compare_digest(invite_code, expected_code):
            flash(
                "Invalid administrator invitation code.",
                "error"
            )
            return render_template("admin_register.html")

        # Validate submitted information.
        if not full_name or not email or len(password) < 12:
            flash(
                "Enter your full name and email, and use a password "
                "with at least 12 characters.",
                "error"
            )
            return render_template("admin_register.html")

        if password != confirm_password:
            flash("The passwords do not match.", "error")
            return render_template("admin_register.html")

        try:
            with get_db() as db:
                db.execute("""
                    INSERT INTO users
                    (full_name, email, password_hash, role, created_at)
                    VALUES (?, ?, ?, 'admin', ?)
                """, (
                    full_name,
                    email,
                    generate_password_hash(password),
                    datetime.utcnow().isoformat(timespec="seconds")
                ))

            flash(
                "Administrator account created. You can now sign in.",
                "success"
            )
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash(
                "An account with that email already exists.",
                "error"
            )

    return render_template("admin_register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if user and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["full_name"]
            session["role"] = user["role"]

            flash("Welcome back.", "success")

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))

            return redirect(url_for("dashboard"))

        flash("Email or password is incorrect.", "error")

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("index"))


# --------------------------------------------------
# CITIZEN DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    with get_db() as db:
        rows = db.execute("""
            SELECT *
            FROM service_requests
            WHERE user_id = ?
            ORDER BY id DESC
        """, (session["user_id"],)).fetchall()

    return render_template(
        "dashboard.html",
        requests=rows
    )


# --------------------------------------------------
# CREATE A SERVICE REQUEST
# --------------------------------------------------

@app.route("/requests/new", methods=["GET", "POST"])
@login_required
def new_request():

    if request.method == "POST":
        category = request.form.get("category", "")
        subject = request.form.get("subject", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()

        uploaded = request.files.get("image")
        image_filename = ""

        # Validate an optional image upload.
        if uploaded and uploaded.filename:
            original = secure_filename(uploaded.filename)

            ext = (
                original.rsplit(".", 1)[-1].lower()
                if "." in original
                else ""
            )

            if ext not in ALLOWED_EXTENSIONS:
                flash(
                    "Upload an image in PNG, JPG, JPEG, GIF, "
                    "or WEBP format.",
                    "error"
                )
                return render_template(
                    "new_request.html",
                    categories=CATEGORIES
                )

            image_filename = secrets.token_hex(12) + "." + ext

        # Validate the request fields.
        if (
            category not in CATEGORIES
            or not subject
            or not description
            or not location
        ):
            flash(
                "Please complete all required fields and choose "
                "a valid category.",
                "error"
            )
            return render_template(
                "new_request.html",
                categories=CATEGORIES
            )

        # Save the image if one was provided.
        if uploaded and uploaded.filename and image_filename:
            uploaded.save(
                os.path.join(UPLOAD_FOLDER, image_filename)
            )

        reference = make_reference()
        now = datetime.utcnow().isoformat(timespec="seconds")

        with get_db() as db:
            db.execute("""
                INSERT INTO service_requests
                (
                    reference,
                    user_id,
                    category,
                    subject,
                    description,
                    location,
                    image_filename,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?)
            """, (
                reference,
                session["user_id"],
                category,
                subject,
                description,
                location,
                image_filename,
                now,
                now
            ))

        flash(
            f"Request submitted. Keep your reference number: {reference}",
            "success"
        )
        return redirect(url_for("dashboard"))

    return render_template(
        "new_request.html",
        categories=CATEGORIES
    )


# --------------------------------------------------
# VIEW REQUEST DETAILS
# --------------------------------------------------

@app.route("/requests/<int:request_id>")
@login_required
def request_detail(request_id):

    with get_db() as db:
        item = db.execute("""
            SELECT r.*, u.full_name, u.email
            FROM service_requests r
            JOIN users u ON u.id = r.user_id
            WHERE r.id = ?
        """, (request_id,)).fetchone()

    if not item:
        abort(404)

    # Citizens may only view their own requests.
    if (
        session.get("role") != "admin"
        and item["user_id"] != session["user_id"]
    ):
        abort(403)

    return render_template(
        "request_detail.html",
        item=item
    )


# --------------------------------------------------
# ADMINISTRATOR DASHBOARD
# --------------------------------------------------

@app.route("/admin")
@admin_required
def admin_dashboard():

    status_filter = request.args.get("status", "")

    with get_db() as db:

        if status_filter in STATUSES:
            rows = db.execute("""
                SELECT r.*, u.full_name, u.email
                FROM service_requests r
                JOIN users u ON u.id = r.user_id
                WHERE r.status = ?
                ORDER BY r.id DESC
            """, (status_filter,)).fetchall()

        else:
            rows = db.execute("""
                SELECT r.*, u.full_name, u.email
                FROM service_requests r
                JOIN users u ON u.id = r.user_id
                ORDER BY r.id DESC
            """).fetchall()

        stats = {
            "total": db.execute(
                "SELECT COUNT(*) FROM service_requests"
            ).fetchone()[0],

            "open": db.execute(
                "SELECT COUNT(*) FROM service_requests "
                "WHERE status != 'Resolved'"
            ).fetchone()[0],

            "pending": db.execute(
                "SELECT COUNT(*) FROM service_requests "
                "WHERE status = 'Pending'"
            ).fetchone()[0],

            "progress": db.execute(
                "SELECT COUNT(*) FROM service_requests "
                "WHERE status = 'In Progress'"
            ).fetchone()[0],

            "resolved": db.execute(
                "SELECT COUNT(*) FROM service_requests "
                "WHERE status = 'Resolved'"
            ).fetchone()[0],
        }

    return render_template(
        "admin.html",
        requests=rows,
        stats=stats,
        statuses=STATUSES,
        status_filter=status_filter
    )


# --------------------------------------------------
# UPDATE REQUEST STATUS
# --------------------------------------------------

@app.route(
    "/admin/requests/<int:request_id>/update",
    methods=["POST"]
)
@admin_required
def update_request(request_id):

    status = request.form.get("status", "")
    note = request.form.get("admin_note", "").strip()

    if status not in STATUSES:
        abort(400)

    with get_db() as db:
        row = db.execute(
            "SELECT id FROM service_requests WHERE id = ?",
            (request_id,)
        ).fetchone()

        if not row:
            abort(404)

        db.execute("""
            UPDATE service_requests
            SET status = ?, admin_note = ?, updated_at = ?
            WHERE id = ?
        """, (
            status,
            note,
            datetime.utcnow().isoformat(timespec="seconds"),
            request_id
        ))

    flash("Request updated.", "success")

    return redirect(
        url_for("request_detail", request_id=request_id)
    )


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(400)
def bad_request(_error):
    return render_template(
        "error.html",
        code=400,
        message="The submitted information is invalid."
    ), 400


@app.errorhandler(403)
def forbidden(_error):
    return render_template(
        "error.html",
        code=403,
        message="You do not have permission to view this page."
    ), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template(
        "error.html",
        code=404,
        message="The page or request could not be found."
    ), 404


@app.errorhandler(413)
def file_too_large(_error):
    return render_template(
        "error.html",
        code=413,
        message=(
            "The uploaded image is too large. "
            "Please choose an image smaller than 5 MB."
        )
    ), 413


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
