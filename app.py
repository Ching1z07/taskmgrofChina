from flask import Flask, render_template, jsonify, request, redirect, url_for, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from werkzeug.utils import secure_filename
from models import db, Task, Category, User, Message
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os, re, secrets, requests as http
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

# ── Paths ─────────────────────────────────────────────────────
DATA_DIR   = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH') or \
             os.path.join(os.path.dirname(__file__), 'instance')
UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')
os.makedirs(DATA_DIR,   exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# ── Brevo config ──────────────────────────────────────────────
BREVO_KEY          = os.getenv('BREVO_API_KEY')
BREVO_SENDER_EMAIL = os.getenv('BREVO_SENDER_EMAIL')
BREVO_SENDER_NAME  = os.getenv('BREVO_SENDER_NAME', 'taskmgr')

# ── App ───────────────────────────────────────────────────────
app = Flask(__name__)

_secret = os.environ.get('SECRET_KEY')
if not _secret:
    raise RuntimeError(
        "SECRET_KEY is not set. Add it in your Render / Railway environment."
    )

app.config.update(
    SECRET_KEY                     = _secret,
    SQLALCHEMY_DATABASE_URI        = f"sqlite:///{os.path.join(DATA_DIR, 'tasks.db')}",
    SQLALCHEMY_TRACK_MODIFICATIONS = False,
    UPLOAD_FOLDER                  = UPLOAD_DIR,
    MAX_CONTENT_LENGTH             = 5 * 1024 * 1024,
)

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins=os.environ.get('CORS_ORIGINS') or None)
limiter  = Limiter(get_remote_address, app=app, default_limits=[])

# ── Security headers ──────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options']         = 'DENY'
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' ws: wss:"
    )
    return response

# ── Login manager ─────────────────────────────────────────────
online_users: dict = {}

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ── DB init ───────────────────────────────────────────────────
with app.app_context():
    db.create_all()
    admin_username = os.environ.get('ADMIN_USERNAME')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    if admin_username and admin_password:
        if not db.session.scalar(db.select(User).where(User.username == admin_username)):
            admin = User(username=admin_username, is_admin=True)
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()

# ── Helpers ───────────────────────────────────────────────────
def validate_password(pw: str):
    if len(pw) < 8:            return "Şifrə ən az 8 simvol olmalıdır"
    if not re.search(r'\d', pw): return "Şifrədə ən az 1 rəqəm olmalıdır"
    if not re.search(r'[A-Z]', pw): return "Şifrədə ən az 1 böyük hərf olmalıdır"
    return None

def validate_email(email: str) -> bool:
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email or ''))

def task_to_dict(task: Task) -> dict:
    return {
        "id":          task.id,
        "name":        task.name,
        "description": task.description,
        "status":      task.status,
        "priority":    task.priority,
        "category_id": task.category_id,
        "image_url":   f"/uploads/{task.image_path}" if task.image_path else None,
        "category": {
            "id":    task.category.id,
            "name":  task.category.name,
            "color": task.category.color,
        } if task.category else None,
        "owner":      task.user.username if task.user else None,
        "created_at": str(task.created_at),
        "updated_at": str(task.updated_at),
    }

def send_reset_email(to_email: str, to_name: str, code: str) -> bool:
    resp = http.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={"api-key": BREVO_KEY, "content-type": "application/json"},
        json={
            "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
            "to": [{"email": to_email, "name": to_name}],
            "subject": "taskmgr — şifrə yeniləmə kodu",
            "htmlContent": f"""
            <div style="background:#08080e;padding:40px 20px;font-family:'Courier New',monospace;min-height:100vh">
              <div style="max-width:420px;margin:0 auto;background:#0f0f1a;border:1px solid #1a1a2e;border-radius:16px;overflow:hidden">
                <div style="height:3px;background:linear-gradient(90deg,#7c6aff,#ff6a9e)"></div>
                <div style="padding:36px 32px">
                  <div style="font-size:1.6rem;font-weight:800;letter-spacing:-0.04em;color:#e8e8f0;margin-bottom:6px">
                    task<span style="color:#7c6aff">mgr</span>
                  </div>
                  <div style="font-size:0.7rem;color:#4a4a62;text-transform:uppercase;letter-spacing:0.15em;margin-bottom:32px">şifrə yeniləmə</div>
                  <p style="color:#9090a8;font-size:0.82rem;line-height:1.7;margin-bottom:28px">
                    Şifrənizi yeniləmək üçün aşağıdakı kodu daxil edin.<br>
                    Kod <strong style="color:#e8e8f0">10 dəqiqə</strong> ərzində etibarlıdır.
                  </p>
                  <div style="background:#08080e;border:1px solid #252538;border-radius:12px;padding:24px;text-align:center;margin-bottom:28px">
                    <div style="font-size:2.4rem;font-weight:800;letter-spacing:0.3em;color:#7c6aff">{code}</div>
                  </div>
                  <p style="color:#4a4a62;font-size:0.7rem;line-height:1.6">
                    Bu emaili siz göndərməmisinizsə, heç nə etməyin — şifrəniz dəyişməyəcək.
                  </p>
                </div>
              </div>
            </div>
            """,
        },
    )
    return resp.ok

# ── Auth routes ───────────────────────────────────────────────
@app.route("/")
@login_required
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if request.method == "POST":
        data     = request.json
        username = (data.get("username") or "").strip()
        email    = (data.get("email") or "").strip().lower()
        if not username or len(username) > 30:
            return jsonify({"error": "İstifadəçi adı 1-30 simvol arasında olmalıdır"}), 400
        if len(email) > 120 or not validate_email(email):
            return jsonify({"error": "Düzgün email daxil edin"}), 400
        if err := validate_password(data.get("password", "")):
            return jsonify({"error": err}), 400
        if db.session.scalar(db.select(User).where(User.username == username)):
            return jsonify({"error": "Bu istifadəçi adı mövcuddur"}), 400
        if db.session.scalar(db.select(User).where(User.email == email)):
            return jsonify({"error": "Bu email artıq qeydiyyatdan keçib"}), 400
        user = User(username=username, email=email)
        user.set_password(data["password"])
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Qeydiyyat uğurlu"}), 201
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        data = request.json
        user = db.session.scalar(db.select(User).where(User.username == data["username"]))
        if not user or user.deleted or not user.check_password(data["password"]):
            return jsonify({"error": "Yanlış istifadəçi adı və ya şifrə"}), 401
        login_user(user)
        return jsonify({"message": "Giriş uğurlu"})
    return render_template("auth.html", mode="login")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/me")
@login_required
def me():
    return jsonify({"username": current_user.username, "is_admin": current_user.is_admin})

@app.route("/delete-account", methods=["DELETE"])
@login_required
def delete_account():
    user          = db.session.get(User, current_user.id)
    deleted_count = db.session.scalar(
        db.select(func.count(User.id)).where(User.deleted == True)
    )
    db.session.execute(db.delete(Task).where(Task.user_id == user.id))
    user.username      = f"user.{31786 + deleted_count}"
    user.email         = None
    user.password_hash = ""
    user.reset_code    = None
    user.reset_expires = None
    user.deleted       = True
    logout_user()
    db.session.commit()
    return jsonify({"message": "Hesab silindi"})

@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == "POST":
        data   = request.json
        action = data.get("action")

        if action == "send":
            user = db.session.scalar(
                db.select(User).where(User.username == data.get("username", ""))
            )
            if not user or not user.email:
                return jsonify({"message": "Hesab mövcuddursa, kodu emailə göndərdik"}), 200
            code               = str(secrets.randbelow(900000) + 100000)
            user.reset_code    = code
            user.reset_expires = datetime.utcnow() + timedelta(minutes=10)
            db.session.commit()
            if not send_reset_email(user.email, user.username, code):
                return jsonify({"error": "Email göndərilə bilmədi"}), 500
            masked = user.email[:2] + "***@" + user.email.split("@")[-1]
            return jsonify({"message": "Kod göndərildi", "masked_email": masked})

        if action == "reset":
            user = db.session.scalar(
                db.select(User).where(User.username == data.get("username", ""))
            )
            if not user or not user.reset_code:
                return jsonify({"error": "Yanlış sorğu"}), 400
            if user.reset_expires < datetime.utcnow():
                return jsonify({"error": "Kodun müddəti bitib, yenidən cəhd edin"}), 400
            if user.reset_code != data.get("code", "").strip():
                return jsonify({"error": "Kod yanlışdır"}), 400
            if err := validate_password(data.get("password", "")):
                return jsonify({"error": err}), 400
            user.set_password(data["password"])
            user.reset_code    = None
            user.reset_expires = None
            db.session.commit()
            return jsonify({"message": "Şifrə yeniləndi"})

        return jsonify({"error": "Yanlış sorğu"}), 400
    return render_template("auth.html", mode="forgot")

# ── Task routes ───────────────────────────────────────────────
@app.route("/tasks", methods=["GET"])
@login_required
def get_tasks():
    stmt = db.select(Task).options(joinedload(Task.category), joinedload(Task.user))
    if not current_user.is_admin:
        stmt = stmt.where(Task.user_id == current_user.id)
    if status := request.args.get('status'):
        stmt = stmt.where(Task.status == status)
    if cat_id := request.args.get('category_id'):
        stmt = stmt.where(Task.category_id == int(cat_id))
    tasks = db.session.scalars(stmt).unique().all()
    return jsonify([task_to_dict(t) for t in tasks])

@app.route("/tasks", methods=["POST"])
@login_required
def create_task():
    name        = request.form.get("name")
    description = request.form.get("description", "")
    status      = request.form.get("status", "pending")
    priority    = request.form.get("priority", "medium")
    category_id = request.form.get("category_id") or None

    image_path = None
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename:
            ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
            if ext not in ALLOWED_EXTENSIONS:
                return jsonify({"error": "Yalnız şəkil fayllarına icazə var (png, jpg, jpeg, gif, webp)"}), 400
            fname      = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
            image_path = fname

    task = Task(
        name=name, description=description, status=status,
        priority=priority, category_id=category_id,
        image_path=image_path, user_id=current_user.id,
    )
    db.session.add(task)
    db.session.commit()
    task = db.session.scalar(
        db.select(Task).options(joinedload(Task.category), joinedload(Task.user))
        .where(Task.id == task.id)
    )
    return jsonify(task_to_dict(task)), 201

@app.route("/tasks/<int:tid>", methods=["PUT"])
@login_required
def update_task(tid):
    task = db.session.get(Task, tid)
    if not task:
        return jsonify({"error": "Tapılmadı"}), 404
    if not current_user.is_admin and task.user_id != current_user.id:
        return jsonify({"error": "İcazə yoxdur"}), 403
    for key in ("name", "description", "status", "priority", "category_id"):
        if key in (data := request.json):
            setattr(task, key, data[key])
    task.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify(task_to_dict(task))

@app.route("/tasks/<int:tid>", methods=["DELETE"])
@login_required
def delete_task(tid):
    task = db.session.get(Task, tid)
    if not task:
        return jsonify({"error": "Tapılmadı"}), 404
    if not current_user.is_admin and task.user_id != current_user.id:
        return jsonify({"error": "İcazə yoxdur"}), 403
    db.session.delete(task)
    db.session.commit()
    return jsonify({"message": f"ID={tid} silindi"})

@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ── Category routes ───────────────────────────────────────────
@app.route("/categories", methods=["GET"])
@login_required
def get_categories():
    rows = db.session.execute(
        db.select(Category, func.count(Task.id).label("task_count"))
        .outerjoin(Task, Task.category_id == Category.id)
        .group_by(Category.id)
    ).all()
    return jsonify([{
        "id":         c.id,
        "name":       c.name,
        "color":      c.color,
        "task_count": count,
    } for c, count in rows])

@app.route("/categories", methods=["POST"])
@login_required
def create_category():
    data  = request.json
    name  = (data.get("name") or "").strip()
    if not name or len(name) > 80:
        return jsonify({"error": "Kateqoriya adı 1-80 simvol arasında olmalıdır"}), 400
    color = data.get("color", "#3498db")
    if not re.match(r'^#[0-9a-fA-F]{6}$', color):
        color = "#3498db"
    cat = Category(name=name, color=color)
    db.session.add(cat)
    db.session.commit()
    return jsonify({"id": cat.id, "name": cat.name, "color": cat.color}), 201

@app.route("/categories/<int:cid>", methods=["DELETE"])
@login_required
def delete_category(cid):
    cat = db.session.get(Category, cid)
    if not cat:
        return jsonify({"error": "Tapılmadı"}), 404
    db.session.delete(cat)
    db.session.commit()
    return jsonify({"message": "Silindi"})

# ── Chat routes ───────────────────────────────────────────────
@app.route("/chat")
@login_required
def chat():
    users = db.session.scalars(
        db.select(User).where(User.id != current_user.id, User.deleted == False)
    ).all()
    return render_template("chat.html", users=users)

@app.route("/chat/history/<int:peer_id>")
@login_required
def chat_history(peer_id):
    me   = current_user.id
    msgs = db.session.scalars(
        db.select(Message)
        .options(joinedload(Message.sender))
        .where(
            ((Message.sender_id == me) & (Message.receiver_id == peer_id)) |
            ((Message.sender_id == peer_id) & (Message.receiver_id == me))
        )
        .order_by(Message.created_at)
    ).all()
    db.session.execute(
        db.update(Message)
        .where(Message.receiver_id == me, Message.sender_id == peer_id, Message.read == False)
        .values(read=True)
    )
    db.session.commit()
    return jsonify([{
        "id":        m.id,
        "sender":    m.sender.username,
        "sender_id": m.sender_id,
        "content":   m.content,
        "time":      m.created_at.strftime("%H:%M"),
    } for m in msgs])

@app.route("/chat/unread")
@login_required
def chat_unread():
    rows = db.session.execute(
        db.select(Message.sender_id, func.count(Message.id))
        .where(Message.receiver_id == current_user.id, Message.read == False)
        .group_by(Message.sender_id)
    ).all()
    return jsonify({str(sid): cnt for sid, cnt in rows})

# ── SocketIO: presence ────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    if current_user.is_authenticated:
        online_users[current_user.id] = current_user.username
        join_room(f"user_{current_user.id}")
        emit("online_list", online_users, broadcast=True)

@socketio.on("disconnect")
def on_disconnect():
    if current_user.is_authenticated:
        online_users.pop(current_user.id, None)
        emit("online_list", online_users, broadcast=True)

# ── SocketIO: messaging ───────────────────────────────────────
@socketio.on("private_message")
def on_private_message(data):
    if not current_user.is_authenticated:
        return
    content     = (data.get("content") or "").strip()
    receiver_id = data.get("receiver_id")
    if not content or not receiver_id or len(content) > 2000:
        return
    msg = Message(sender_id=current_user.id, receiver_id=receiver_id, content=content)
    db.session.add(msg)
    db.session.commit()
    payload = {
        "id":        msg.id,
        "sender":    current_user.username,
        "sender_id": current_user.id,
        "content":   content,
        "time":      msg.created_at.strftime("%H:%M"),
    }
    emit("new_message", payload, to=f"user_{receiver_id}")
    emit("new_message", payload, to=f"user_{current_user.id}")

@socketio.on("typing")
def on_typing(data):
    if current_user.is_authenticated:
        emit("typing", {"from": current_user.id}, to=f"user_{data.get('receiver_id')}")

@socketio.on("stop_typing")
def on_stop_typing(data):
    if current_user.is_authenticated:
        emit("stop_typing", {"from": current_user.id}, to=f"user_{data.get('receiver_id')}")

# ── SocketIO: WebRTC signaling ────────────────────────────────
@socketio.on("call_invite")
def on_call_invite(data):
    if current_user.is_authenticated and (rid := data.get("receiver_id")):
        emit("call_invite", {"from_id": current_user.id, "from_name": current_user.username},
             to=f"user_{rid}")

@socketio.on("call_accept")
def on_call_accept(data):
    if current_user.is_authenticated:
        emit("call_accept", {"from_id": current_user.id}, to=f"user_{data.get('caller_id')}")

@socketio.on("call_reject")
def on_call_reject(data):
    if current_user.is_authenticated:
        emit("call_reject", {"from_id": current_user.id}, to=f"user_{data.get('caller_id')}")

@socketio.on("call_end")
def on_call_end(data):
    if current_user.is_authenticated:
        emit("call_end", {"from_id": current_user.id}, to=f"user_{data.get('peer_id')}")

@socketio.on("webrtc_offer")
def on_webrtc_offer(data):
    if current_user.is_authenticated:
        emit("webrtc_offer", {"sdp": data.get("sdp"), "from_id": current_user.id},
             to=f"user_{data.get('receiver_id')}")

@socketio.on("webrtc_answer")
def on_webrtc_answer(data):
    if current_user.is_authenticated:
        emit("webrtc_answer", {"sdp": data.get("sdp"), "from_id": current_user.id},
             to=f"user_{data.get('caller_id')}")

@socketio.on("ice_candidate")
def on_ice_candidate(data):
    if current_user.is_authenticated:
        emit("ice_candidate", {"candidate": data.get("candidate"), "from_id": current_user.id},
             to=f"user_{data.get('peer_id')}")

# ── Dev server ────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5500))
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
