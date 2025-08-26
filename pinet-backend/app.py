"""
PiNet Mining – Sample Backend (Flask + SQLAlchemy)
--------------------------------------------------
Demo backend that implements:
- User auth (register/login with JWT), profile, incremental user_number starting at 112131
- Mining sessions (24h), server-side reward calculation, claim logic
- Wallet balances (coins, pi, usdt) and transaction log
- Conversions: coins→pi, pi→usdt
- Withdraw endpoints (disabled: 'coming soon')
- Referrals (invited / active) and rewards for active friends
- Leaderboard (top 10) and user rank with an offset start for large rank numbers
- News feed (GET public, POST admin)

⚠️ This is a simple demo (single file). For production add: HTTPS, proper CORS, rate limiting,
password reset flows, email/Telegram verification, migrations (Alembic), etc.
"""
from __future__ import annotations
import os, time, datetime as dt
from functools import wraps
from typing import Optional

from flask import Flask, jsonify, request, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

# ---------------------------- Config ----------------------------
DB_URL = os.getenv("DATABASE_URL", "sqlite:///pinet_demo.db")
SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
TOKEN_EXPIRE_HOURS = 72

DURATION_SECONDS = 24*60*60  # 24h mining session
RATE_PER_SEC = 0.05          # coins per second (demo)
REF_REWARD = 30              # coins per active friend
COINS_PER_PI = 100
USDT_PER_PI = 5
USER_NUMBER_START = 112_131  # starting visible user id
LEADERBOARD_OFFSET = 0       # set e.g. 112_121 to inflate displayed ranks

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_SORT_KEYS'] = False

db = SQLAlchemy(app)

# ---------------------------- Models ----------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    user_number = db.Column(db.Integer, unique=True, index=True)  # visible number (starts 112131)
    coins = db.Column(db.Float, default=0)
    pi = db.Column(db.Float, default=0)
    usdt = db.Column(db.Float, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    last_active_at = db.Column(db.DateTime)

    # mining
    mining_start = db.Column(db.DateTime)  # null if no active session

    # referral
    ref_code = db.Column(db.String(20), unique=True)
    referred_by = db.Column(db.String(20), db.ForeignKey('user.ref_code'))

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=False)
    kind = db.Column(db.String(20))  # earn/swap/withdraw/info
    amount = db.Column(db.Float, default=0)
    note = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

class Referral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inviter_code = db.Column(db.String(20), index=True)
    invitee_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

# ---------------------------- Utilities ----------------------------

def create_token(user: User) -> str:
    payload = {
        'uid': user.id,
        'exp': dt.datetime.utcnow() + dt.timedelta(hours=TOKEN_EXPIRE_HOURS)
    }
    return jwt.encode(payload, SECRET, algorithm='HS256')


def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth.split(' ', 1)[1]
        if not token:
            return jsonify({'error': 'missing token'}), 401
        try:
            payload = jwt.decode(token, SECRET, algorithms=['HS256'])
        except Exception as e:
            return jsonify({'error': 'invalid token'}), 401
        user = User.query.get(payload['uid'])
        if not user:
            return jsonify({'error': 'user not found'}), 404
        g.user = user
        user.last_active_at = dt.datetime.utcnow()
        db.session.commit()
        return f(*args, **kwargs)
    return wrapper


def push_tx(user: User, kind: str, amount: float, note: str = ""):
    tx = Transaction(user_id=user.id, kind=kind, amount=amount, note=note)
    db.session.add(tx)


def ensure_db():
    db.create_all()
    # bootstrap a first admin if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            first_name='Admin',
            last_name='User',
            is_admin=True,
            user_number=USER_NUMBER_START - 1,  # reserve below start
            ref_code='ADMINREF'
        )
        db.session.add(admin)
        db.session.commit()

# ---------------------------- Auth ----------------------------
@app.post('/register')
def register():
    data = request.get_json(force=True)
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    ref = (data.get('ref') or '').strip() or None
    if not username or not password:
        return jsonify({'error': 'username/password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'username taken'}), 409

    # assign next visible user_number starting from USER_NUMBER_START
    max_num = db.session.query(db.func.max(User.user_number)).scalar() or (USER_NUMBER_START - 1)
    user_number = max(max_num + 1, USER_NUMBER_START)

    # generate ref code (simple demo)
    ref_code = f"REF{int(time.time()*1000)%10_000_000:07d}"

    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        first_name='User', last_name='',
        user_number=user_number,
        ref_code=ref_code
    )
    db.session.add(user)
    db.session.flush()  # get user.id

    # process referral if provided
    if ref:
        inviter = User.query.filter_by(ref_code=ref).first()
        if inviter and inviter.id != user.id:
            db.session.add(Referral(inviter_code=ref, invitee_user_id=user.id, active=False))
            push_tx(inviter, 'info', 0, f'New invitee joined via {ref}')

    db.session.commit()
    token = create_token(user)
    return jsonify({'token': token, 'ref_code': user.ref_code, 'user_number': user.user_number})


@app.post('/login')
def login():
    data = request.get_json(force=True)
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'invalid credentials'}), 401
    token = create_token(user)
    return jsonify({'token': token})

# ---------------------------- Profile ----------------------------
@app.get('/me')
@auth_required
def me():
    u = g.user
    return jsonify({
        'username': u.username,
        'first_name': u.first_name,
        'last_name': u.last_name,
        'user_number': u.user_number,
        'ref_code': u.ref_code
    })

@app.put('/me')
@auth_required
def update_me():
    data = request.get_json(force=True)
    u = g.user
    u.first_name = (data.get('first_name') or u.first_name)
    u.last_name = (data.get('last_name') or u.last_name)
    db.session.commit()
    return jsonify({'ok': True})

# ---------------------------- Mining ----------------------------
@app.post('/mining/start')
@auth_required
def mining_start():
    u = g.user
    if u.mining_start:
        return jsonify({'error': 'already mining', 'started_at': u.mining_start.isoformat()}), 400
    u.mining_start = dt.datetime.utcnow()
    push_tx(u, 'info', 0, 'Started 24h mining')
    db.session.commit()
    return jsonify({'started_at': u.mining_start.isoformat(), 'duration_sec': DURATION_SECONDS, 'rate_per_sec': RATE_PER_SEC})


def _mining_metrics(u: User):
    if not u.mining_start:
        return dict(elapsed=0, remaining=DURATION_SECONDS, progress=0.0, reward_now=0.0, completed=False)
    now = dt.datetime.utcnow()
    elapsed = max(0, int((now - u.mining_start).total_seconds()))
    clamped = min(elapsed, DURATION_SECONDS)
    remaining = max(0, DURATION_SECONDS - elapsed)
    reward_now = clamped * RATE_PER_SEC
    progress = clamped / DURATION_SECONDS
    return dict(elapsed=elapsed, remaining=remaining, progress=progress, reward_now=reward_now, completed=elapsed >= DURATION_SECONDS)

@app.get('/mining/status')
@auth_required
def mining_status():
    return jsonify(_mining_metrics(g.user))

@app.post('/mining/claim')
@auth_required
def mining_claim():
    u = g.user
    if not u.mining_start:
        return jsonify({'error': 'no active mining'}), 400
    m = _mining_metrics(u)
    if m['reward_now'] > 0:
        u.coins += m['reward_now']
        push_tx(u, 'earn', m['reward_now'], 'Mining session reward')
    u.mining_start = None
    db.session.commit()
    return jsonify({'claimed': round(m['reward_now'], 2), 'coins': round(u.coins, 2)})

# ---------------------------- Wallet / Conversions ----------------------------
@app.get('/wallet')
@auth_required
def wallet():
    u = g.user
    # latest 50 txs
    txs = Transaction.query.filter_by(user_id=u.id).order_by(Transaction.id.desc()).limit(50).all()
    return jsonify({
        'coins': round(u.coins, 2),
        'pi': round(u.pi, 4),
        'usdt': round(u.usdt, 2),
        'rates': {'coins_per_pi': COINS_PER_PI, 'usdt_per_pi': USDT_PER_PI},
        'tx': [
            dict(kind=t.kind, amount=round(t.amount, 4), note=t.note, created_at=t.created_at.isoformat())
            for t in txs
        ]
    })

@app.post('/convert/coins-to-pi')
@auth_required
def coins_to_pi():
    u = g.user
    data = request.get_json(force=True)
    coins = int(max(0, data.get('coins', 0)))
    if coins <= 0:
        return jsonify({'error': 'amount required'}), 400
    if coins > u.coins:
        return jsonify({'error': 'not enough coins'}), 400
    pi = coins / COINS_PER_PI
    u.coins -= coins
    u.pi += pi
    push_tx(u, 'swap', pi, f'Converted {coins} coins → {pi:.2f} Pi')
    db.session.commit()
    return jsonify({'coins': round(u.coins, 2), 'pi': round(u.pi, 4)})

@app.post('/convert/pi-to-usdt')
@auth_required
def pi_to_usdt():
    u = g.user
    data = request.get_json(force=True)
    pi = float(max(0, data.get('pi', 0)))
    if pi <= 0:
        return jsonify({'error': 'amount required'}), 400
    if pi > u.pi:
        return jsonify({'error': 'not enough Pi'}), 400
    usdt = pi * USDT_PER_PI
    u.pi -= pi
    u.usdt += usdt
    push_tx(u, 'swap', usdt, f'Converted {pi:.2f} Pi → {usdt:.2f} USDT')
    db.session.commit()
    return jsonify({'pi': round(u.pi, 4), 'usdt': round(u.usdt, 2)})

@app.post('/withdraw/pi')
@auth_required
def withdraw_pi():
    return jsonify({'ok': False, 'message': 'Withdraw Pi is coming soon'}), 202

@app.post('/withdraw/usdt')
@auth_required
def withdraw_usdt():
    return jsonify({'ok': False, 'message': 'Withdraw USDT is coming soon'}), 202

# ---------------------------- Referrals & Friends ----------------------------
@app.get('/friends')
@auth_required
def friends_info():
    u = g.user
    invited = Referral.query.filter_by(inviter_code=u.ref_code).count()
    active = Referral.query.filter_by(inviter_code=u.ref_code, active=True).count()
    return jsonify({'invited': invited, 'active': active, 'ref_code': u.ref_code})

@app.post('/friends/mock-activate')
@auth_required
def friends_mock_activate():
    """For QA/demo only: mark one of your invitees active and grant reward"""
    u = g.user
    ref = Referral.query.filter_by(inviter_code=u.ref_code, active=False).first()
    if not ref:
        # if none, fabricate a virtual referral row
        fake_user = User(username=f"bot_{int(time.time())}", password_hash=generate_password_hash('x'), user_number=None, ref_code=f"BOT{int(time.time())}")
        db.session.add(fake_user); db.session.flush()
        ref = Referral(inviter_code=u.ref_code, invitee_user_id=fake_user.id, active=False)
        db.session.add(ref)
    ref.active = True
    u.coins += REF_REWARD
    push_tx(u, 'earn', REF_REWARD, 'Active friend reward')
    db.session.commit()
    return jsonify({'active_now': True, 'coins': round(u.coins, 2)})

# ---------------------------- Leaderboard ----------------------------
@app.get('/leaderboard')
@auth_required
def leaderboard():
    # top 10 by total coins (not including Pi/USDT for fairness)
    top = User.query.order_by(User.coins.desc()).limit(10).all()
    top_list = [
        {
            'rank': i+1,
            'username': u.username,
            'coins': round(u.coins, 2)
        } for i, u in enumerate(top)
    ]

    # compute current user's rank
    u = g.user
    higher = User.query.filter(User.coins > u.coins).count()
    my_rank = higher + 1
    displayed_rank = my_rank + LEADERBOARD_OFFSET

    return jsonify({'top10': top_list, 'yourRank': displayed_rank})

# ---------------------------- News ----------------------------
@app.get('/news')
@auth_required
def list_news():
    items = News.query.order_by(News.id.desc()).limit(20).all()
    return jsonify([
        {'id': n.id, 'title': n.title, 'body': n.body, 'created_at': n.created_at.isoformat()}
        for n in items
    ])

@app.post('/admin/news')
@auth_required
def add_news():
    if not g.user.is_admin:
        return jsonify({'error': 'admin only'}), 403
    data = request.get_json(force=True)
    title = (data.get('title') or '').strip()
    body = (data.get('body') or '').strip()
    if not title or not body:
        return jsonify({'error': 'title/body required'}), 400
    n = News(title=title, body=body)
    db.session.add(n)
    db.session.commit()
    return jsonify({'ok': True, 'id': n.id})

# ---------------------------- App bootstrap ----------------------------
@app.get('/')
def root():
    return jsonify({'ok': True, 'service': 'PiNet mining backend demo'})

if __name__ == '__main__':
    ensure_db()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)
