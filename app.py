from flask import Flask, render_template, jsonify, request, redirect, url_for, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from models import db, Task, Category, User, Message
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os, re, random, requests as http

load_dotenv()

DATA_DIR = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', os.path.join(os.path.dirname(__file__), 'instance'))
UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(DATA_DIR, 'tasks.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'sizin-gizli-açar-123')
app.config['UPLOAD_FOLDER'] = UPLOAD_DIR
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

online_users = {}  # {user_id: username}

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    User.__table__.create(db.engine, checkfirst=True)
    db.create_all()
    if not User.query.filter_by(username="Ching1z_7").first():
        admin = User(username="Ching1z_7", is_admin=True)
        admin.set_password("Domino")
        db.session.add(admin)
        db.session.commit()

@app.route("/")
@login_required
def home():
    return render_template("index.html")

BREVO_KEY         = os.getenv("BREVO_API_KEY")
BREVO_SENDER_EMAIL = os.getenv("BREVO_SENDER_EMAIL")
BREVO_SENDER_NAME  = os.getenv("BREVO_SENDER_NAME", "taskmgr")

def send_reset_email(to_email, to_name, code):
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
            """
        }
    )
    return resp.ok

def validate_password(pw):
    if len(pw) < 8:
        return "Şifrə ən az 8 simvol olmalıdır"
    if not re.search(r'\d', pw):
        return "Şifrədə ən az 1 rəqəm olmalıdır"
    if not re.search(r'[A-Z]', pw):
        return "Şifrədə ən az 1 böyük hərf olmalıdır"
    return None

def validate_email(email):
    return re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email or '')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.json
        email = (data.get("email") or "").strip().lower()
        if not validate_email(email):
            return jsonify({"error": "Düzgün email daxil edin"}), 400
        err = validate_password(data.get("password", ""))
        if err:
            return jsonify({"error": err}), 400
        if User.query.filter_by(username=data["username"]).first():
            return jsonify({"error": "Bu istifadəçi adı mövcuddur"}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Bu email artıq qeydiyyatdan keçib"}), 400
        user = User(username=data["username"], email=email)
        user.set_password(data["password"])
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Qeydiyyat uğurlu"}), 201
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.json
        user = User.query.filter_by(username=data["username"]).first()
        if not user or user.deleted or not user.check_password(data["password"]):
            return jsonify({"error": "Yanlış istifadəçi adı və ya şifrə"}), 401
        login_user(user)
        return jsonify({"message": "Giriş uğurlu"})
    return render_template("auth.html", mode="login")

@app.route("/delete-account", methods=["DELETE"])
@login_required
def delete_account():
    user = User.query.get(current_user.id)
    deleted_count = User.query.filter_by(deleted=True).count()
    anon_name = f"user.{31786 + deleted_count}"
    Task.query.filter_by(user_id=user.id).delete()
    user.username      = anon_name
    user.email         = None
    user.password_hash = ""
    user.reset_code    = None
    user.reset_expires = None
    user.deleted       = True
    logout_user()
    db.session.commit()
    return jsonify({"message": "Hesab silindi"})

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        data = request.json
        action = data.get("action")

        if action == "send":
            user = User.query.filter_by(username=data.get("username", "")).first()
            if not user:
                return jsonify({"error": "Bu istifadəçi adı tapılmadı"}), 404
            if not user.email:
                return jsonify({"error": "Bu hesaba email bağlı deyil"}), 400
            code = str(random.randint(100000, 999999))
            user.reset_code = code
            user.reset_expires = datetime.utcnow() + timedelta(minutes=10)
            db.session.commit()
            ok = send_reset_email(user.email, user.username, code)
            if not ok:
                return jsonify({"error": "Email göndərilə bilmədi"}), 500
            masked = user.email[:2] + "***@" + user.email.split("@")[-1]
            return jsonify({"message": "Kod göndərildi", "masked_email": masked})

        if action == "reset":
            user = User.query.filter_by(username=data.get("username", "")).first()
            if not user or not user.reset_code:
                return jsonify({"error": "Yanlış sorğu"}), 400
            if user.reset_expires < datetime.utcnow():
                return jsonify({"error": "Kodun müddəti bitib, yenidən cəhd edin"}), 400
            if user.reset_code != data.get("code", "").strip():
                return jsonify({"error": "Kod yanlışdır"}), 400
            err = validate_password(data.get("password", ""))
            if err:
                return jsonify({"error": err}), 400
            user.set_password(data["password"])
            user.reset_code = None
            user.reset_expires = None
            db.session.commit()
            return jsonify({"message": "Şifrə yeniləndi"})

        return jsonify({"error": "Yanlış sorğu"}), 400
    return render_template("auth.html", mode="forgot")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/me")
@login_required
def me():
    return jsonify({"username": current_user.username, "is_admin": current_user.is_admin})

@app.route("/tasks", methods=["GET"])
@login_required
def get_tasks():
    query = Task.query if current_user.is_admin else Task.query.filter_by(user_id=current_user.id)
    status = request.args.get('status')
    cat_id = request.args.get('category_id')
    if status:
        query = query.filter_by(status=status)
    if cat_id:
        query = query.filter_by(category_id=cat_id)
    return jsonify([task_to_dict(t) for t in query.all()])

@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route("/tasks", methods=["POST"])
@login_required
def create_task():
    name = request.form.get("name")
    description=request.form.get("description", "")
    status = request.form.get("status", "pending")
    priority = request.form.get("priority", "medium")
    category_id = request.form.get("category_id") or None

    image_path = None
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename:
            filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_path = filename

    task = Task(
        name=name,
        status=status,
        priority=priority,
        category_id=category_id,
        image_path=image_path,
        user_id=current_user.id,
        description=description
    )
    db.session.add(task)
    db.session.commit()
    return jsonify(task_to_dict(task)), 201

@app.route("/tasks/<int:tid>", methods=["PUT"])
@login_required
def update_task(tid):
    task = Task.query.get(tid)
    if not task:
        return jsonify({"error": "Tapılmadı"}), 404
    if not current_user.is_admin and task.user_id != current_user.id:
        return jsonify({"error": "İcazə yoxdur"}), 403
    data = request.json
    for key in ["name", "description", "status", "priority", "category_id"]:
        if key in data:
            setattr(task, key, data[key])
    task.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify(task_to_dict(task)), 200

@app.route("/tasks/<int:tid>", methods=["DELETE"])
@login_required
def delete_task(tid):
    task = Task.query.get(tid)
    if not task:
        return jsonify({"error": "Tapılmadı"}), 404
    if not current_user.is_admin and task.user_id != current_user.id:
        return jsonify({"error": "İcazə yoxdur"}), 403
    db.session.delete(task)
    db.session.commit()
    return jsonify({"message": f"ID={tid} silindi"}), 200

@app.route("/categories", methods=["GET"])
@login_required
def get_categories():
    cats = Category.query.all()
    return jsonify([{
        "id": c.id,
        "name": c.name,
        "color": c.color,
        "task_count": len(c.tasks)
    } for c in cats])

@app.route("/categories", methods=["POST"])
@login_required
def create_category():
    data = request.json
    cat = Category(name=data["name"], color=data.get("color", "#3498db"))
    db.session.add(cat)
    db.session.commit()
    return jsonify({"id": cat.id, "name": cat.name, "color": cat.color}), 201

@app.route("/categories/<int:cid>", methods=["DELETE"])
@login_required
def delete_category(cid):
    cat = Category.query.get(cid)
    if not cat:
        return jsonify({"error": "Tapılmadı"}), 404
    db.session.delete(cat)
    db.session.commit()
    return jsonify({"message": "Silindi"}), 200

# ── Chat routes ──────────────────────────────────────────────
@app.route("/chat")
@login_required
def chat():
    users = User.query.filter(User.id != current_user.id, User.deleted == False).all()
    return render_template("chat.html", users=users)

@app.route("/chat/history/<int:peer_id>")
@login_required
def chat_history(peer_id):
    msgs = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == peer_id)) |
        ((Message.sender_id == peer_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.created_at).all()
    Message.query.filter_by(receiver_id=current_user.id, sender_id=peer_id, read=False).update({"read": True})
    db.session.commit()
    return jsonify([{
        "id": m.id,
        "sender": m.sender.username,
        "sender_id": m.sender_id,
        "content": m.content,
        "time": m.created_at.strftime("%H:%M")
    } for m in msgs])

@app.route("/chat/unread")
@login_required
def chat_unread():
    rows = db.session.query(Message.sender_id, db.func.count(Message.id))\
        .filter_by(receiver_id=current_user.id, read=False)\
        .group_by(Message.sender_id).all()
    return jsonify({str(sid): cnt for sid, cnt in rows})

# ── SocketIO events ──────────────────────────────────────────
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

@socketio.on("private_message")
def on_private_message(data):
    if not current_user.is_authenticated:
        return
    content = (data.get("content") or "").strip()
    receiver_id = data.get("receiver_id")
    if not content or not receiver_id:
        return
    msg = Message(sender_id=current_user.id, receiver_id=receiver_id, content=content)
    db.session.add(msg)
    db.session.commit()
    payload = {
        "id": msg.id,
        "sender": current_user.username,
        "sender_id": current_user.id,
        "content": content,
        "time": msg.created_at.strftime("%H:%M")
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

# ─────────────────────────────────────────────────────────────

def task_to_dict(task):
    return {
        "id": task.id,
        "name": task.name,
        "description": task.description,
        "status": task.status,
        "priority": task.priority,
        "category_id": task.category_id,
        "image_url": f"/uploads/{task.image_path}" if task.image_path else None,
        "category": {
            "id": task.category.id,
            "name": task.category.name,
            "color": task.category.color
        } if task.category else None,
        "owner": task.user.username if task.user else None,
        "created_at": str(task.created_at),
        "updated_at": str(task.updated_at)
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5500))
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)