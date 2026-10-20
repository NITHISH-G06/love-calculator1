import os
import time
import csv
import io
import hashlib
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify, session,
    redirect, url_for, make_response
)

import config
import database
import love_engine

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = config.SECRET_KEY

# Configure session cookies for security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False, # Set True if running behind HTTPS in production
    PERMANENT_SESSION_LIFETIME=86400 * 7 # 7 days
)

# Initialize database schema on startup
with app.app_context():
    database.init_db()

# Rate limiting storage (in-memory tracking: { ip: [timestamp, ...] })
RATE_LIMITS = {}
LOGIN_ATTEMPTS = {} # { ip: { count: int, lockout_until: float } }

def get_client_ip():
    """Retrieve client IP address, handling proxies."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def anonymize_ip(ip: str) -> str:
    """Create a non-reversible salted hash of the IP for privacy protection."""
    salt = config.SECRET_KEY[:16]
    return hashlib.sha256(f"{ip}:{salt}".encode("utf-8")).hexdigest()[:12]

def simplify_user_agent(ua_string: str) -> str:
    """Classify user agent into a clean device category."""
    if not ua_string:
        return "Unknown"
    ua = ua_string.lower()
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        return "📱 Mobile"
    elif "tablet" in ua or "ipad" in ua:
        return "📟 Tablet"
    elif "macintosh" in ua or "mac os" in ua:
        return "💻 Mac"
    elif "windows" in ua:
        return "🖥️ Windows"
    elif "linux" in ua:
        return "🐧 Linux"
    return "🌐 Desktop"

def check_rate_limit(ip: str) -> bool:
    """Return True if under rate limit, False if exceeded."""
    now = time.time()
    window = 60 # 1 minute
    history = RATE_LIMITS.get(ip, [])
    # Keep only timestamps within the last minute
    history = [t for t in history if now - t < window]
    if len(history) >= config.MAX_SUBMISSIONS_PER_MINUTE:
        RATE_LIMITS[ip] = history
        return False
    history.append(now)
    RATE_LIMITS[ip] = history
    return True

def login_required(f):
    """Decorator to protect owner-only admin views."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            if request.path.startswith("/admin/api/"):
                return jsonify({"error": "Unauthorized. Please log in as site owner."}), 401
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def set_security_headers(response):
    """Inject modern web security headers on all responses."""
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# =========================================================================
# VISITOR ROUTES
# =========================================================================

@app.route("/")
def index():
    """Welcoming, playful landing page with love calculator."""
    return render_template("index.html")

@app.route("/api/calculate", methods=["POST"])
def calculate():
    """
    Public calculation endpoint.
    Saves submitted pair to owner-only DB and returns this visitor's result.
    Does NOT reveal any other visitor data.
    """
    client_ip = get_client_ip()
    
    # 1. Rate Limiting Protection
    if not check_rate_limit(client_ip):
        return jsonify({
            "success": False,
            "error": "Cupid needs to catch his breath! 🕊️ Please wait a moment before calculating again."
        }), 429
        
    data = request.get_json(silent=True) or request.form
    
    # 2. Anti-spam honeypot detection
    honeypot = data.get("company_website", "") or data.get("honeypot", "")
    if honeypot:
        # Silently reject bot submissions without polluting database
        return jsonify({
            "success": True,
            "score": 42,
            "verdict": "Curious Bot Detected 🤖❤️",
            "emoji": "🤖💔",
            "reading": "Cupid loves humans more than automated scrapers!",
            "advice": "Try turning off robot mode."
        })
        
    your_name = data.get("your_name", "")
    crush_name = data.get("crush_name", "")
    
    # 3. Input Validation & Sanitization
    is_valid, validation_result = love_engine.validate_names(your_name, crush_name)
    if not is_valid:
        return jsonify({
            "success": False,
            "error": validation_result
        }), 400
        
    clean_n1, clean_n2 = validation_result
    
    # 4. Calculation Algorithm
    result = love_engine.calculate_love(clean_n1, clean_n2)
    
    # 5. Persistent Storage for Site Owner Review
    ip_hash = anonymize_ip(client_ip)
    ua_summary = simplify_user_agent(request.headers.get("User-Agent", ""))
    
    try:
        sub_id = database.save_submission(
            your_name=clean_n1,
            crush_name=clean_n2,
            score=result["score"],
            verdict=result["verdict"],
            emoji=result["emoji"],
            reading=result["reading"],
            ip_hash=ip_hash,
            user_agent=ua_summary
        )
    except Exception as e:
        app.logger.error(f"Database error saving submission: {e}")
        # Even if DB fails, calculation result still displays gracefully
    
    # Return ONLY the current visitor's own calculation
    return jsonify({
        "success": True,
        "score": result["score"],
        "verdict": result["verdict"],
        "emoji": result["emoji"],
        "reading": result["reading"],
        "advice": result["advice"],
        "your_name": clean_n1,
        "crush_name": clean_n2,
        "is_easter_egg": result.get("is_easter_egg", False)
    })

# =========================================================================
# OWNER-ONLY ADMIN ROUTES & AUTHENTICATION
# =========================================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Secure login page for site owner."""
    client_ip = get_client_ip()
    
    # Check brute-force lockout
    now = time.time()
    attempt_info = LOGIN_ATTEMPTS.get(client_ip, {"count": 0, "lockout_until": 0})
    if attempt_info["lockout_until"] > now:
        remaining = int(attempt_info["lockout_until"] - now)
        return render_template(
            "admin_login.html",
            error=f"Too many failed login attempts. Locked out for {remaining} seconds."
        ), 429
        
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if database.verify_admin(username, password):
            # Reset failed attempts
            LOGIN_ATTEMPTS.pop(client_ip, None)
            session.permanent = True
            session["is_admin"] = True
            session["admin_username"] = username
            return redirect(url_for("admin_dashboard"))
        else:
            # Increment failed attempts
            attempt_info["count"] += 1
            if attempt_info["count"] >= 5:
                attempt_info["lockout_until"] = now + 300 # 5 minutes lockout
                LOGIN_ATTEMPTS[client_ip] = attempt_info
                return render_template(
                    "admin_login.html",
                    error="Maximum login attempts exceeded. Please try again in 5 minutes."
                ), 429
            LOGIN_ATTEMPTS[client_ip] = attempt_info
            return render_template(
                "admin_login.html",
                error="Invalid owner username or password."
            ), 401
            
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    """Secure logout."""
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin")
@login_required
def admin_dashboard():
    """Site owner dashboard displaying all submissions and analytics."""
    stats = database.get_stats()
    submissions, total_count = database.get_submissions(limit=50)
    return render_template(
        "admin_dashboard.html",
        stats=stats,
        submissions=submissions,
        total_count=total_count,
        admin_username=session.get("admin_username", "Owner")
    )

@app.route("/admin/api/submissions", methods=["GET"])
@login_required
def api_submissions():
    """Owner API for live filtering, searching, and pagination of submissions."""
    search = request.args.get("search", "").strip()
    sort = request.args.get("sort", "newest")
    limit = min(int(request.args.get("limit", 50)), 100)
    offset = int(request.args.get("offset", 0))
    
    rows, total_matching = database.get_submissions(
        search=search, sort=sort, limit=limit, offset=offset
    )
    stats = database.get_stats()
    
    return jsonify({
        "success": True,
        "submissions": rows,
        "total": total_matching,
        "stats": stats
    })

@app.route("/admin/api/submissions/<int:sub_id>/delete", methods=["POST"])
@login_required
def api_delete_submission(sub_id):
    """Owner endpoint to delete a submission."""
    success = database.delete_submission(sub_id)
    if success:
        return jsonify({"success": True, "message": "Submission deleted."})
    return jsonify({"success": False, "error": "Submission not found."}), 404

@app.route("/admin/api/clear-all", methods=["POST"])
@login_required
def api_clear_all():
    """Owner endpoint to clear submissions for testing or resetting."""
    database.clear_all_submissions()
    return jsonify({"success": True, "message": "All submissions cleared."})

@app.route("/admin/api/change-password", methods=["POST"])
@login_required
def api_change_password():
    """Owner endpoint to update admin password."""
    data = request.get_json(silent=True) or request.form
    current_pass = data.get("current_password", "")
    new_pass = data.get("new_password", "")
    username = session.get("admin_username")
    
    if not database.verify_admin(username, current_pass):
        return jsonify({"success": False, "error": "Current password is incorrect."}), 400
        
    if len(new_pass) < 8:
        return jsonify({"success": False, "error": "New password must be at least 8 characters long."}), 400
        
    database.update_admin_password(username, new_pass)
    return jsonify({"success": True, "message": "Password updated successfully."})

@app.route("/admin/export-csv")
@login_required
def export_csv():
    """Direct CSV download of all saved visitor submissions for the site owner."""
    rows, _ = database.get_submissions(limit=10000)
    
    si = io.StringIO()
    cw = csv.writer(si)
    
    # Write header
    cw.writerow([
        "ID", "Your Name", "Crush Name", "Love Score (%)",
        "Verdict", "Reading", "Device", "Submitted At (UTC)"
    ])
    
    for r in rows:
        cw.writerow([
            r["id"],
            r["your_name"],
            r["crush_name"],
            f"{r['score']}%",
            r["verdict"],
            r["reading"],
            r["user_agent"],
            r["created_at"]
        ])
        
    output = make_response(si.getvalue())
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output.headers["Content-Disposition"] = f"attachment; filename=love_calculator_submissions_{timestamp}.csv"
    output.headers["Content-type"] = "text/csv; charset=utf-8"
    return output

if __name__ == "__main__":
    print(f"Starting Love Calculator server on http://localhost:{config.APP_PORT}")
    print(f"Admin area: http://localhost:{config.APP_PORT}/admin (Default: {config.ADMIN_USERNAME} / {config.ADMIN_PASSWORD})")
    app.run(host=config.APP_HOST, port=config.APP_PORT, debug=config.DEBUG)
