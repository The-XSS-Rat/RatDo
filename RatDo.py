# app.py — Flask To‑Do Easy Lab (Pretty)
# -------------------------------------------------------------
# ⚠️ This is intentionally vulnerable for teaching purposes.
# Built to be tiny, pretty, and perfect for beginner bug bounty labs.
#
# Included vulnerabilities you can demonstrate:
#  - Stored XSS: task titles are rendered with |safe (see render in index()).
#  - Missing CSRF: state‑changing routes have no CSRF protection.
#  - IDOR / BAC: edit/delete/toggle routes do not verify task ownership.
#  - Weak session management: basic cookie session, no advanced safeguards.
#
# Notes:
#  - Uses SQLite (file: todo.db)
#  - One file, no templates folder — HTML is embedded for easy drop‑in.
#  - Tailwind via CDN for a clean, modern UI.
# -------------------------------------------------------------

from flask import Flask, g, request, redirect, url_for, render_template_string, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

APP_NAME = "RatTasks"
DATABASE = "todo.db"
SECRET = "dev-secret-change-me"  # change in prod

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET)

# ------------------------ DB Helpers ------------------------

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            done INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )
    db.commit()

# ------------------------ Utilities ------------------------

def current_user_id():
    return session.get('uid')

from functools import wraps

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user_id():
            flash("Please log in first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# ------------------------ HTML Shell ------------------------

BASE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{{ title or app_name }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
      body { font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, 'Helvetica Neue', Arial, 'Noto Sans', 'Apple Color Emoji', 'Segoe UI Emoji'; }
    </style>
  </head>
  <body class="min-h-screen bg-gradient-to-b from-slate-50 to-slate-100">
    <header class="sticky top-0 backdrop-blur bg-white/70 border-b border-slate-200 z-10">
      <div class="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
        <a href="{{ url_for('index') }}" class="text-xl font-extrabold tracking-tight">🐀 {{ app_name }}</a>
        <nav class="flex items-center gap-3 text-sm">
          {% if uid %}
            <span class="text-slate-600">Hi, <strong>{{ username }}</strong></span>
            <a href="{{ url_for('logout') }}" class="px-3 py-1 rounded-lg bg-slate-900 text-white hover:bg-slate-800">Logout</a>
          {% else %}
            <a href="{{ url_for('login') }}" class="px-3 py-1 rounded-lg border border-slate-300 hover:bg-white">Login</a>
            <a href="{{ url_for('register') }}" class="px-3 py-1 rounded-lg bg-slate-900 text-white hover:bg-slate-800">Sign up</a>
          {% endif %}
        </nav>
      </div>
    </header>

    <main class="max-w-4xl mx-auto px-4 py-8">
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          <div class="space-y-2 mb-6">
            {% for cat, msg in messages %}
              <div class="p-3 rounded-xl border {{ 'border-amber-300 bg-amber-50' if cat=='warning' else 'border-emerald-300 bg-emerald-50' }} text-slate-800">{{ msg }}</div>
            {% endfor %}
          </div>
        {% endif %}
      {% endwith %}

      {{ body|safe }}
    </main>

    <footer class="py-8 text-center text-xs text-slate-500">Built for teaching. Do not use in production.</footer>
  </body>
</html>
"""

# ------------------------ Routes: Auth ------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Username and password required.', 'warning')
            return redirect(url_for('register'))
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)',
                (username, generate_password_hash(password), datetime.utcnow().isoformat())
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash('Username already taken.', 'warning')
            return redirect(url_for('register'))
        flash('Account created. Please log in.', 'ok')
        return redirect(url_for('login'))

    body = f"""
    <div class='max-w-md mx-auto'>
      <h1 class='text-3xl font-bold mb-6'>Create your account</h1>
      <form method='post' class='space-y-4 bg-white p-6 rounded-2xl shadow'>
        <div>
          <label class='block text-sm font-medium mb-1'>Username</label>
          <input name='username' class='w-full rounded-xl border border-slate-300 px-3 py-2' placeholder='ratmaster' />
        </div>
        <div>
          <label class='block text-sm font-medium mb-1'>Password</label>
          <input type='password' name='password' class='w-full rounded-xl border border-slate-300 px-3 py-2' />
        </div>
        <button class='w-full rounded-xl bg-slate-900 text-white py-2 font-semibold hover:bg-slate-800'>Sign up</button>
        <p class='text-sm text-slate-600 text-center'>Already have an account? <a href='{url_for('login')}' class='underline'>Log in</a></p>
      </form>
    </div>
    """
    return render_template_string(BASE, title=f"Sign up • {APP_NAME}", body=body, app_name=APP_NAME, uid=current_user_id(), username=session.get('uname'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        row = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if row and check_password_hash(row['password_hash'], password):
            session['uid'] = row['id']
            session['uname'] = row['username']
            flash('Welcome back!', 'ok')
            return redirect(url_for('index'))
        flash('Invalid credentials.', 'warning')
        return redirect(url_for('login'))

    body = f"""
    <div class='max-w-md mx-auto'>
      <h1 class='text-3xl font-bold mb-6'>Log in</h1>
      <form method='post' class='space-y-4 bg-white p-6 rounded-2xl shadow'>
        <div>
          <label class='block text-sm font-medium mb-1'>Username</label>
          <input name='username' class='w-full rounded-xl border border-slate-300 px-3 py-2' placeholder='ratmaster' />
        </div>
        <div>
          <label class='block text-sm font-medium mb-1'>Password</label>
          <input type='password' name='password' class='w-full rounded-xl border border-slate-300 px-3 py-2' />
        </div>
        <button class='w-full rounded-xl bg-slate-900 text-white py-2 font-semibold hover:bg-slate-800'>Log in</button>
        <p class='text-sm text-slate-600 text-center'>No account yet? <a href='{url_for('register')}' class='underline'>Sign up</a></p>
      </form>
    </div>
    """
    return render_template_string(BASE, title=f"Log in • {APP_NAME}", body=body, app_name=APP_NAME, uid=current_user_id(), username=session.get('uname'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'ok')
    return redirect(url_for('login'))

# ------------------------ Routes: Tasks ------------------------

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    db = get_db()
    uid = current_user_id()

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        if not title:
            flash('Task title required.', 'warning')
            return redirect(url_for('index'))
        db.execute('INSERT INTO tasks (user_id, title, created_at) VALUES (?, ?, ?)', (uid, title, datetime.utcnow().isoformat()))
        db.commit()
        flash('Task added.', 'ok')
        return redirect(url_for('index'))

    # NOTE: Deliberate XSS risk: in the HTML below, we will render title with |safe.
    tasks = db.execute('SELECT * FROM tasks WHERE user_id = ? ORDER BY done, id DESC', (uid,)).fetchall()

    items_html = "\n".join([
        f"""
        <li class='group flex items-center justify-between p-3 bg-white rounded-xl border border-slate-200 hover:shadow-sm transition'>
          <div class='flex items-center gap-3'>
            <input type='checkbox' onclick="window.location='{url_for('toggle', task_id=row['id'])}'" {'checked' if row['done'] else ''} class='h-4 w-4 rounded border-slate-300' />
            <span class='{'line-through text-slate-400' if row['done'] else 'text-slate-800'}'>{{{{ (""" + row['title'] + """) | safe }}}}</span>
          </div>
          <div class='opacity-0 group-hover:opacity-100 transition flex items-center gap-2'>
            <a class='px-2 py-1 text-xs rounded-lg border' href='{url_for('edit', task_id=row['id'])}'>Edit</a>
            <a class='px-2 py-1 text-xs rounded-lg border border-red-300 text-red-700' href='{url_for('delete', task_id=row['id'])}'>Delete</a>
          </div>
        </li>
        """ for row in tasks
    ])

    body = f"""
    <div class='flex items-center justify-between mb-6'>
      <div>
        <h1 class='text-3xl font-extrabold'>Your tasks</h1>
        <p class='text-slate-600'>Quick, clean, and a little bit dangerous (for learning 😉).</p>
      </div>
      <a href='{url_for('seed_demo')}' class='text-sm underline'>Seed demo tasks</a>
    </div>

    <form method='post' class='mb-6 bg-white p-4 rounded-2xl shadow flex items-center gap-3'>
      <input name='title' class='flex-1 rounded-xl border border-slate-300 px-3 py-2' placeholder='Write a task… (try <script>alert(1)</script>)' />
      <button class='rounded-xl bg-slate-900 text-white px-4 py-2 font-semibold hover:bg-slate-800'>Add</button>
    </form>

    <ul class='space-y-2'>
      {items_html or "<li class='text-slate-500'>No tasks yet. Add your first one!</li>"}
    </ul>
    """

    return render_template_string(BASE, title=f"Tasks • {APP_NAME}", body=body, app_name=APP_NAME, uid=uid, username=session.get('uname'))

@app.route('/toggle/<int:task_id>')
@login_required
def toggle(task_id):
    db = get_db()
    row = db.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()  # ❌ no ownership check
    if not row:
        flash('Task not found.', 'warning')
        return redirect(url_for('index'))
    new_val = 0 if row['done'] else 1
    db.execute('UPDATE tasks SET done = ? WHERE id = ?', (new_val, task_id))
    db.commit()
    return redirect(url_for('index'))

@app.route('/delete/<int:task_id>')
@login_required
def delete(task_id):
    db = get_db()
    db.execute('DELETE FROM tasks WHERE id = ?', (task_id,))  # ❌ no ownership check
    db.commit()
    flash('Task deleted.', 'ok')
    return redirect(url_for('index'))

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit(task_id):
    db = get_db()
    row = db.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()  # ❌ no ownership check
    if not row:
        flash('Task not found.', 'warning')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        if not title:
            flash('Title required.', 'warning')
            return redirect(url_for('edit', task_id=task_id))
        db.execute('UPDATE tasks SET title = ? WHERE id = ?', (title, task_id))
        db.commit()
        flash('Task updated.', 'ok')
        return redirect(url_for('index'))

    body = f"""
    <div class='max-w-lg mx-auto'>
      <h1 class='text-3xl font-bold mb-6'>Edit task</h1>
      <form method='post' class='space-y-4 bg-white p-6 rounded-2xl shadow'>
        <div>
          <label class='block text-sm font-medium mb-1'>Title</label>
          <input name='title' value='{row['title']}' class='w-full rounded-xl border border-slate-300 px-3 py-2' />
        </div>
        <div class='flex items-center gap-3'>
          <a href='{url_for('index')}' class='px-4 py-2 rounded-xl border'>Cancel</a>
          <button class='px-4 py-2 rounded-xl bg-slate-900 text-white'>Save</button>
        </div>
      </form>
    </div>
    """
    return render_template_string(BASE, title=f"Edit • {APP_NAME}", body=body, app_name=APP_NAME, uid=current_user_id(), username=session.get('uname'))

# ------------------------ Demo Seeder ------------------------

@app.route('/seed-demo')
@login_required
def seed_demo():
    db = get_db()
    uid = current_user_id()
    seeds = [
        (uid, "Welcome to <b>RatTasks</b>!", datetime.utcnow().isoformat()),
        (uid, "This one is <i>italic</i>.", datetime.utcnow().isoformat()),
        (uid, "Try a harmless script: <script>alert('XSS')</script>", datetime.utcnow().isoformat()),
    ]
    db.executemany('INSERT INTO tasks (user_id, title, created_at) VALUES (?, ?, ?)', seeds)
    db.commit()
    flash('Seeded a few tasks (including an XSS demo).', 'ok')
    return redirect(url_for('index'))

# ------------------------ App Entry ------------------------
if __name__ == '__main__':
    # Initialize the DB inside an application context
    with app.app_context():
        init_db()

    print("\n➡  Running RatTasks on http://127.0.0.1:5000  (Flask dev server)\n")
    app.run(host="0.0.0.0", port=5000)
