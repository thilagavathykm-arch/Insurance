"""Insurance portal: customer login, register insurance, submit claim, renew, inquiry."""
import re
import secrets 
import secrets
from datetime import date
from functools import wraps

from flask import (Flask, abort, flash, redirect, render_template, request, send_from_directory,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import config
import db
from agent import tools as T
from agent.claim_agent import ClaimApproverAgent, SLOTS
from agent.core import policy_status
from agent.registration_agent import RegistrationAgent
from agent.renewal_agent import RenewalAgent

app = Flask(__name__)
app.secret_key = config.secret_key()
app.config["MAX_CONTENT_LENGTH"] = 60 * 1024 * 1024
db.init_db()
SAMPLES_DIR = config.BASE_DIR / "samples"


# ----------------------------------------------------------------- helpers
@app.before_request
def csrf_protect():
    if request.method == "POST":
        if not session.get("csrf") or request.form.get("csrf") != session["csrf"]:
            abort(400, "Your session expired. Please go back, refresh the page and try again.")


@app.context_processor
def inject():
    session.setdefault("csrf", secrets.token_hex(16))
    return dict(csrf=session["csrf"], user=current_user(), plans=config.PLANS, money=T.money,
                pretty=T.pretty_date, policy_status=policy_status, accept=".pdf,.doc,.docx,.png,.jpg,.jpeg,.webp")


def current_user():
    uid = session.get("uid")
    return db.q("SELECT * FROM users WHERE id=?", (uid,), one=True) if uid else None


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not current_user():
            flash("Please log in first.", "warn")
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def upload(field):
    return T.save_upload(request.files.get(field))


def my_policies():
    return db.q("SELECT * FROM policies WHERE user_id=? ORDER BY id DESC", (session["uid"],))


# ------------------------------------------------------------ account pages
@app.route("/")
def home():
    return redirect(url_for("dashboard")) if current_user() else render_template("home.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        f = {k: request.form.get(k, "").strip() for k in ("name", "email", "phone")}
        pw = request.form.get("password", "")
        err = None
        if len(f["name"]) < 3:
            err = "Please enter your full name."
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", f["email"]):
            err = "Please enter a valid email address."
        elif not re.fullmatch(r"\+?[\d\s-]{8,15}", f["phone"]):
            err = "Please enter a valid phone number (8-15 digits)."
        elif len(pw) < 8 or not re.search(r"\d", pw) or not re.search(r"[A-Za-z]", pw):
            err = "Password must be at least 8 characters with letters and numbers."
        elif pw != request.form.get("password2"):
            err = "The two passwords do not match."
        elif db.q("SELECT 1 FROM users WHERE email=?", (f["email"].lower(),)):
            err = "An account with this email already exists. Please log in."
        if err:
            flash(err, "error")
            return render_template("signup.html", f=f)
        uid = db.run("INSERT INTO users(name,email,phone,password_hash) VALUES(?,?,?,?)",
                     (f["name"], f["email"].lower(), f["phone"], generate_password_hash(pw)))
        session.clear()
        session["uid"] = uid
        flash("Welcome! Your account is ready.", "ok")
        return redirect(url_for("dashboard"))
    return render_template("signup.html", f={})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db.q("SELECT * FROM users WHERE email=?", (request.form.get("email", "").strip().lower(),), one=True)
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            session.clear()
            session["uid"] = u["id"]
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    pols = my_policies()
    claims = db.q("SELECT c.* FROM claims c JOIN policies p ON p.id=c.policy_id WHERE p.user_id=? ORDER BY c.id DESC LIMIT 5",
                  (session["uid"],))
    return render_template("dashboard.html", policies=pols, claims=claims)


# --------------------------------------------------------- 1. register insurance
@app.route("/insure", methods=["GET", "POST"])
@login_required
def insure():
    form = {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("name", "eid", "plan", "eid_mode")}
        form["eid_mode"] = form["eid_mode"] if form["eid_mode"] in ("single", "two") else "single"
        try:
            if form["eid_mode"] == "single":
                eid_files = [upload("eid_single")]
            else:
                eid_files = [upload("eid_front"), upload("eid_back")]
            visa = upload("visa")
        except ValueError as e:
            flash(str(e), "error")
            return render_template("insure.html", f=form)
        res = RegistrationAgent().run(session["uid"], form["name"], form["eid"], form["plan"], form["eid_mode"], eid_files, visa)
        return render_template("result.html", res=res, title="Register Insurance", retry=url_for("insure"),
                               policy_number=res.data.get("policy_number"))
    return render_template("insure.html", f=form)


# ------------------------------------------------------------ 2. submit claim
@app.route("/claim", methods=["GET", "POST"])
@login_required
def claim():
    if request.method == "POST":
        try:
            files = {slot: upload(slot) for slot in SLOTS}
        except ValueError as e:
            flash(str(e), "error")
            return render_template("claim.html", slots=SLOTS, policies=my_policies(), number=request.form.get("policy_number", ""))
        res = ClaimApproverAgent().run(session["uid"], request.form.get("policy_number", ""), files)
        return render_template("result.html", res=res, title="Submit Claim", retry=url_for("claim"))
    return render_template("claim.html", slots=SLOTS, policies=my_policies(), number=request.args.get("policy", ""))


# ------------------------------------------------------------ 3. renew policy
@app.route("/renew", methods=["GET", "POST"])
@login_required
def renew():
    if request.method == "POST":
        try:
            visa = upload("visa")
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("renew"))
        if request.form.get("pay") != "yes":
            flash("Please tick the payment confirmation box to renew.", "error")
            return redirect(url_for("renew", policy=request.form.get("policy_number", "")))
        res = RenewalAgent().run(session["uid"], request.form.get("policy_number", ""), request.form.get("plan", ""), visa)
        return render_template("result.html", res=res, title="Renew Policy", retry=url_for("renew"),
                               policy_number=res.data.get("policy_number"))
    return render_template("renew.html", policies=my_policies(), number=request.args.get("policy", ""), today=date.today().isoformat(),
                           window=config.RENEWAL_WINDOW_DAYS)


# ----------------------------------------------------------- 4. policy inquiry
@app.route("/inquiry", methods=["GET", "POST"])
@login_required
def inquiry():
    if request.method == "POST":
        return redirect(url_for("inquiry_detail", number=request.form.get("policy_number", "").strip().upper()))
    return render_template("inquiry.html", policies=my_policies())


@app.route("/inquiry/<number>")
@login_required
def inquiry_detail(number):
    p = db.q("SELECT * FROM policies WHERE number=? AND user_id=?", (number, session["uid"]), one=True)
    if not p:
        flash(f"We could not find policy '{number}' under your account.", "error")
        return redirect(url_for("inquiry"))
    import json
    claims = db.q("SELECT * FROM claims WHERE policy_id=? ORDER BY id DESC", (p["id"],))
    renewals = db.q("SELECT * FROM renewals WHERE policy_id=? ORDER BY id DESC", (p["id"],))
    return render_template("policy.html", p=p, claims=claims, renewals=renewals, json=json,
                           available=p["annual_limit"] - p["used_amount"])


@app.route("/policy/<number>/certificate")
@login_required
def certificate(number):
    p = db.q("SELECT * FROM policies WHERE number=? AND user_id=?", (number, session["uid"]), one=True)
    if not p:
        abort(404)
    return render_template("certificate.html", p=p)


@app.route("/claims/<claim_number>")
@login_required
def claim_detail(claim_number):
    import json
    c = db.q("SELECT c.*, p.number pnum, p.holder_name FROM claims c JOIN policies p ON p.id=c.policy_id "
             "WHERE c.claim_number=? AND p.user_id=?", (claim_number, session["uid"]), one=True)
    if not c:
        abort(404)
    return render_template("claim_detail.html", c=c, steps=json.loads(c["trace"]))


# ---------------------------------------------------------- sample documents
@app.route("/samples")
@login_required
def samples():
    groups = {}
    if SAMPLES_DIR.exists():
        for f in sorted(SAMPLES_DIR.rglob("*")):
            if f.is_file() and f.suffix != ".md" and f.name != "README.txt":
                groups.setdefault(str(f.parent.relative_to(SAMPLES_DIR)), []).append(str(f.relative_to(SAMPLES_DIR)))
    readme = (SAMPLES_DIR / "README.txt").read_text() if (SAMPLES_DIR / "README.txt").exists() else ""
    return render_template("samples.html", groups=groups, readme=readme)


@app.route("/samples/file/<path:name>")
@login_required
def sample_file(name):
    return send_from_directory(SAMPLES_DIR, name, as_attachment=request.args.get("dl") == "1")


@app.errorhandler(413)
def too_big(e):
    flash("The files are too large. Each file must be under 10 MB.", "error")
    return redirect(request.referrer or url_for("home"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
