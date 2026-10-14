import os, secrets, string
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import quote

import psycopg
import requests
from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', '')
if len(app.secret_key) < 32:
    raise RuntimeError('Set FLASK_SECRET_KEY in .env to at least 32 characters.')
DB_URL = os.getenv('DATABASE_URL', '')
SB_URL = os.getenv('SUPABASE_URL', '').rstrip('/')
SB_KEY = os.getenv('SUPABASE_SERVICE_ROLE_KEY', '')
BUCKET = os.getenv('SUPABASE_MEDIA_BUCKET', 'school-media')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '')
app.config.update(MAX_CONTENT_LENGTH=8*1024*1024, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE','false').lower()=='true')
if not DB_URL:
    raise RuntimeError('DATABASE_URL is missing in .env')

# This app uses its own portal_* tables and the existing public.students table.
# It does not drop or recreate any existing school tables.
SCHEMA = [
'''CREATE TABLE IF NOT EXISTS portal_accounts (
 id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','student','staff')),
 student_id INTEGER UNIQUE REFERENCES public.students(id) ON DELETE CASCADE,
 active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())''',
'''CREATE TABLE IF NOT EXISTS portal_exam_results (
 id BIGSERIAL PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES public.students(id) ON DELETE CASCADE,
 exam_name TEXT NOT NULL, term TEXT NOT NULL, subject TEXT NOT NULL,
 score NUMERIC(6,2) NOT NULL CHECK(score>=0 AND score<=100), grade TEXT DEFAULT '',
 published BOOLEAN NOT NULL DEFAULT FALSE, result_type TEXT NOT NULL DEFAULT 'End-of-term',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(student_id,exam_name,term,subject))''',
'''CREATE TABLE IF NOT EXISTS portal_media (
 id BIGSERIAL PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL,
 image_url TEXT NOT NULL, storage_path TEXT NOT NULL, alt_text TEXT DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())''',
'''CREATE TABLE IF NOT EXISTS portal_clubs (
 id BIGSERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, description TEXT DEFAULT '',
 leader TEXT DEFAULT '', media_id BIGINT REFERENCES portal_media(id) ON DELETE SET NULL,
 active BOOLEAN NOT NULL DEFAULT TRUE)''',
'''CREATE TABLE IF NOT EXISTS portal_settings(setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL DEFAULT '')''',
'''CREATE TABLE IF NOT EXISTS portal_audit (
 id BIGSERIAL PRIMARY KEY, actor TEXT DEFAULT '', action TEXT NOT NULL,
 details TEXT DEFAULT '', ip_address TEXT DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())''',
]
def connect(): return psycopg.connect(DB_URL, connect_timeout=10)
def init_db():
    with connect() as conn:
        with conn.cursor() as c:
            for sql in SCHEMA: c.execute(sql)
            c.execute("ALTER TABLE portal_exam_results ADD COLUMN IF NOT EXISTS grade TEXT DEFAULT ''")
            defaults = {'school_name':'Waddilove High School','school_motto':'Learning, character and service',
                        'school_address':'','school_phone':'','school_email':'',
                        'homepage_intro':'Welcome to Waddilove High School.',
                        'results_notice':'Only published end-of-term examination results are shown.',
                        'school_logo_left_url':'','school_logo_right_url':'','homepage_background_url':'','pass_mark':'50'}
            for k,v in defaults.items(): c.execute('INSERT INTO portal_settings(setting_key,setting_value) VALUES(%s,%s) ON CONFLICT DO NOTHING',(k,v))
            c.execute('SELECT id FROM portal_accounts WHERE username=%s',(ADMIN_USERNAME,))
            if not c.fetchone():
                if len(ADMIN_PASSWORD) < 12: raise RuntimeError('Set ADMIN_PASSWORD in .env to at least 12 characters before first start.')
                c.execute("INSERT INTO portal_accounts(username,full_name,password_hash,role) VALUES(%s,%s,%s,'admin')",
                          (ADMIN_USERNAME,'School Administrator',generate_password_hash(ADMIN_PASSWORD)))
def get_settings():
    with connect() as conn:
        with conn.cursor() as c: c.execute('SELECT setting_key,setting_value FROM portal_settings'); return dict(c.fetchall())
@app.context_processor
def inject_globals(): return {'user':session.get('user'),'settings':get_settings()}
def audit(action, details=''):
    try:
        with connect() as conn:
            with conn.cursor() as c: c.execute('INSERT INTO portal_audit(actor,action,details,ip_address) VALUES(%s,%s,%s,%s)',
                (session.get('user',{}).get('username','anonymous'),action,details[:700],request.remote_addr or ''))
    except Exception: app.logger.exception('Audit logging failed')
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user'): return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user'): return redirect(url_for('login', next=request.path))
        if session['user']['role'] != 'admin': abort(403)
        return fn(*args, **kwargs)
    return wrapper
def csrf_token():
    if '_csrf' not in session: session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']
app.jinja_env.globals['csrf_token'] = csrf_token
@app.before_request
def check_csrf():
    if request.method == 'POST' and (not session.get('_csrf') or not secrets.compare_digest(session['_csrf'], request.form.get('_csrf',''))): abort(400, 'Form expired. Refresh and try again.')

BASE = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · {{ settings.get('school_name','Waddilove High School') }}</title><style>
:root{--navy:#101a33;--blue:#203b67;--gold:#e7c16b;--bg:#f3f6fb;--line:#dce4ef}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#1c2940;font:15px Segoe UI,Arial,sans-serif;line-height:1.5}.top{background:linear-gradient(110deg,var(--navy),var(--blue));padding:15px 5%;color:#fff;display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap}.school-brand{display:flex;align-items:center;justify-content:center;gap:14px;min-width:260px}.school-brand-text{text-align:center;font-size:18px;font-weight:800;line-height:1.25}.school-logo-box{width:68px;height:68px;flex:0 0 68px;border-radius:10px;background:#fff;display:flex;align-items:center;justify-content:center;overflow:hidden;padding:5px}.school-logo-box img{width:100%;height:100%;object-fit:contain;display:block}.report-card{background:#fff;border:2px solid #203b67;border-radius:12px;padding:24px;margin:18px 0;break-inside:avoid}.report-heading{text-align:center;border-bottom:2px solid #203b67;padding-bottom:14px;margin-bottom:16px}.report-heading h2{margin:4px 0}.status-pass{color:#11643c;background:#dff7e9}.status-fail{color:#9d2222;background:#ffe5e5}.status-pill{display:inline-block;padding:4px 9px;border-radius:30px;font-weight:800;font-size:12px}.report-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:15px 0}.report-summary>div{background:#f2f5fa;padding:12px;border-radius:8px}.report-summary strong{display:block;font-size:20px}.top nav{display:flex;gap:13px;flex-wrap:wrap}.top a{color:#fff;text-decoration:none;font-size:13px}.top nav{display:flex;gap:13px;flex-wrap:wrap}.top a{color:#fff;text-decoration:none;font-size:13px}.wrap{max-width:1200px;margin:25px auto;padding:0 16px}.hero{background:linear-gradient(130deg,var(--navy),#31558b);color:#fff;border-radius:17px;padding:32px;margin-bottom:18px}.home-hero{min-height:390px;display:flex;flex-direction:column;justify-content:center;background-size:cover;background-position:center;background-repeat:no-repeat;box-shadow:0 18px 40px #101a3333;text-shadow:0 2px 12px #0008}.home-hero p{max-width:720px;font-size:18px}.hero h1{font-size:clamp(28px,4vw,43px);margin:0 0 8px}.hero p{color:#e1e9f6}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.card{background:#fff;border:1px solid var(--line);border-radius:13px;padding:18px;margin-bottom:15px;box-shadow:0 4px 15px #1223420a}.stat{font-size:30px;font-weight:800;color:var(--navy)}.muted{font-size:12px;color:#6b778b}label{display:block;font-weight:650;font-size:13px;margin:11px 0 5px}input,select,textarea{width:100%;padding:10px;border:1px solid #cbd5e1;border-radius:8px;font:inherit}textarea{min-height:75px}button,.btn{display:inline-block;background:var(--blue);color:white;border:0;border-radius:8px;padding:10px 13px;font-weight:700;cursor:pointer;text-decoration:none}.gold{background:var(--gold);color:#18233a}.light{background:#eaf0f8;color:#20365c}.danger{background:#a52c2c}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}th{background:#edf1f7}.flash{padding:11px 13px;background:#e2f5eb;color:#155c40;border-radius:8px;margin:10px 0}.error{background:#ffedeb;color:#8b281f}.media{width:100%;max-height:220px;object-fit:cover;border-radius:8px}.footer{text-align:center;padding:25px;color:#6b778b;font-size:12px}.credential{border:2px dashed #8290a5;padding:18px;margin:12px 0;break-inside:avoid}.credential h3{margin-top:0}.pill{display:inline-block;background:#eaf0f8;padding:3px 8px;border-radius:99px;font-size:12px}@media(max-width:600px){.hero{padding:22px}.card{padding:14px}}@media print{.top,form,.no-print,.footer{display:none!important}body{background:white}.wrap{max-width:none;margin:0}.card{box-shadow:none}.credential{border:1px solid #777}}
</style></head><body><header class="top"><div class="school-brand"><div class="school-logo-box">{% if settings.get('school_logo_left_url') %}<img src="{{ settings.get('school_logo_left_url') }}" alt="School logo left">{% endif %}</div><div class="school-brand-text">{{ settings.get('school_name','Waddilove High School') }}<div class="muted" style="color:#dce6f5;font-weight:400">{{ settings.get('school_motto','School portal') }}</div></div><div class="school-logo-box">{% if settings.get('school_logo_right_url') %}<img src="{{ settings.get('school_logo_right_url') }}" alt="School logo right">{% endif %}</div></div><nav><a href="{{ url_for('home') }}">Home</a><a href="{{ url_for('clubs') }}">Clubs</a><a href="{{ url_for('gallery') }}">Gallery</a>{% if user %}<a href="{{ url_for('results') }}">Results</a>{% if user.role=='admin' %}<a href="{{ url_for('admin') }}">Admin</a>{% endif %}<a href="{{ url_for('logout') }}">Sign out</a>{% else %}<a href="{{ url_for('login') }}">Sign in</a>{% endif %}</nav></header><main class="wrap">{% with ms=get_flashed_messages(with_categories=true) %}{% for cat,msg in ms %}<div class="flash {{ 'error' if cat=='error' else '' }}">{{ msg }}</div>{% endfor %}{% endwith %}{{ body|safe }}</main><footer class="footer">{{ settings.get('school_name','Waddilove High School') }} · Secure school portal</footer></body></html>'''
def page(title, template, **ctx): return render_template_string(BASE,title=title,body=render_template_string(template,**ctx))
def upload_image(file):
    if not SB_URL or not SB_KEY: raise ValueError('Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env to enable image uploads.')
    name=secure_filename(file.filename or '')
    if not name or '.' not in name or name.rsplit('.',1)[1].lower() not in {'png','jpg','jpeg','webp','gif'}: raise ValueError('Choose a PNG, JPG, JPEG, WEBP or GIF image.')
    path=f"{datetime.now(timezone.utc):%Y/%m}/{secrets.token_hex(10)}-{name}"
    url=f"{SB_URL}/storage/v1/object/{quote(BUCKET,safe='')}/{quote(path,safe='/')}"
    r=requests.post(url,headers={'Authorization':f'Bearer {SB_KEY}','apikey':SB_KEY,'Content-Type':file.mimetype or 'application/octet-stream','x-upsert':'false'},data=file.read(),timeout=30)
    if r.status_code not in (200,201): raise RuntimeError('Supabase Storage upload failed. Check that the bucket exists and the service-role key is correct.')
    return path, f"{SB_URL}/storage/v1/object/public/{quote(BUCKET,safe='')}/{quote(path,safe='/')}"
def random_password(length=12):
    alphabet=string.ascii_letters+string.digits+'!@#$%'
    while True:
        p=''.join(secrets.choice(alphabet) for _ in range(length))
        if any(x.islower() for x in p) and any(x.isupper() for x in p) and any(x.isdigit() for x in p): return p

def media_rows():
    with connect() as conn:
        with conn.cursor() as c: c.execute('SELECT id,title,category,image_url,storage_path,alt_text FROM portal_media ORDER BY id DESC'); return c.fetchall()
@app.route('/')
def home():
    with connect() as conn:
        with conn.cursor() as c: c.execute('SELECT cl.name,cl.description,cl.leader,m.image_url FROM portal_clubs cl LEFT JOIN portal_media m ON m.id=cl.media_id WHERE cl.active=TRUE ORDER BY cl.name LIMIT 6'); clubs_data=c.fetchall()
    return page('Home',r'''<section class="hero home-hero" style="{% if settings.get('homepage_background_url') %}background-image:linear-gradient(100deg,rgba(9,19,42,.88),rgba(22,43,77,.55)),url('{{ settings.get('homepage_background_url') }}');{% endif %}"><h1>{{ settings.get('school_name','Waddilove High School') }}</h1><p>{{ settings.get('homepage_intro','Welcome to our school.') }}</p><a class="btn gold" href="{{ url_for('login') }}">Student results portal</a>{% if user and user.role=='admin' %} <a class="btn" href="{{ url_for('admin') }}">Admin control centre</a>{% endif %}</section><div class="grid"><div class="card"><h2>End-of-term results</h2><p>Private access to published examination results.</p><a class="btn" href="{{ url_for('login') }}">Open results</a></div><div class="card"><h2>Clubs and societies</h2><a class="btn light" href="{{ url_for('clubs') }}">Explore clubs</a></div><div class="card"><h2>School gallery</h2><a class="btn light" href="{{ url_for('gallery') }}">View photographs</a></div></div>{% if clubs_data %}<h2>Clubs and societies</h2><div class="grid">{% for c in clubs_data %}<div class="card">{% if c[3] %}<img class="media" src="{{ c[3] }}" alt="">{% endif %}<h3>{{ c[0] }}</h3><p>{{ c[1] }}</p><div class="muted">{{ c[2] }}</div></div>{% endfor %}</div>{% endif %}''',clubs_data=clubs_data)
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        with connect() as conn:
            with conn.cursor() as c: c.execute('SELECT id,username,full_name,password_hash,role,active,student_id FROM portal_accounts WHERE username=%s',(request.form.get('username','').strip(),)); row=c.fetchone()
        if row and row[5] and check_password_hash(row[3],request.form.get('password','')):
            session.clear(); session['user']={'id':row[0],'username':row[1],'full_name':row[2],'role':row[4],'student_id':row[6]}; csrf_token(); audit('login',row[4])
            dest=request.args.get('next',''); return redirect(dest if dest.startswith('/') and not dest.startswith('//') else (url_for('admin') if row[4]=='admin' else url_for('results')))
        flash('Incorrect username/password or inactive account.','error')
    return page('Sign in',r'''<div class="card" style="max-width:460px;margin:35px auto"><h1>Secure sign in</h1><p class="muted">Students use their full name as username and the password printed on their credential slip.</p><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><label>Username</label><input name="username" autocomplete="username" required><label>Password</label><input type="password" name="password" autocomplete="current-password" required><div class="actions"><button>Sign in</button></div></form></div>''')
@app.route('/logout')
@login_required
def logout(): audit('logout'); session.clear(); return redirect(url_for('home'))
@app.route('/results')
@login_required
def results():
    u=session['user']
    settings_now=get_settings()
    try: pass_mark=float(settings_now.get('pass_mark','50'))
    except (TypeError,ValueError): pass_mark=50.0
    with connect() as conn:
        with conn.cursor() as c:
            if u['role']=='admin':
                c.execute('SELECT s.student_number,s.full_name,r.exam_name,r.term,r.subject,r.score,r.grade,r.published FROM portal_exam_results r JOIN public.students s ON s.id=r.student_id ORDER BY s.full_name,r.term,r.exam_name,r.subject LIMIT 2000')
            elif u['role']=='student' and u.get('student_id'):
                c.execute('SELECT s.student_number,s.full_name,r.exam_name,r.term,r.subject,r.score,r.grade,r.published FROM portal_exam_results r JOIN public.students s ON s.id=r.student_id WHERE r.student_id=%s AND r.published=TRUE ORDER BY r.term,r.exam_name,r.subject',(u['student_id'],))
            else: c.execute('SELECT NULL WHERE FALSE')
            rows=c.fetchall()
    # Group each student's marks into report cards for each end-of-term examination.
    cards=[]
    if u['role']=='student' and rows:
        grouped={}
        for r in rows:
            key=(r[2],r[3])
            grouped.setdefault(key,[]).append(r)
        for (exam,term),items in grouped.items():
            total=sum(float(x[5]) for x in items)
            average=total/len(items) if items else 0
            cards.append({'exam':exam,'term':term,'student':items[0][1],'number':items[0][0],
                          'subjects':items,'total':total,'average':average,
                          'overall':'PASS' if average>=pass_mark else 'FAIL'})
    return page('Results',r'''<div class="hero"><h1>{{ 'Results management' if user.role=='admin' else 'My report cards' }}</h1><p>{{ settings.get('results_notice','Published end-of-term examination results appear here.') }} Pass mark: {{ pass_mark }}%.</p></div>
{% if user.role=='admin' %}<div class="card"><div class="table-wrap"><table><tr><th>Student</th><th>Number</th><th>Exam</th><th>Term</th><th>Subject</th><th>Score</th><th>Grade</th><th>Pass/fail</th><th>Publication</th></tr>{% for r in rows %}<tr><td>{{ r[1] }}</td><td>{{ r[0] }}</td><td>{{ r[2] }}</td><td>{{ r[3] }}</td><td>{{ r[4] }}</td><td>{{ '%.2f'|format(r[5]) }}%</td><td>{{ r[6] or '—' }}</td><td><span class="status-pill {{ 'status-pass' if r[5]>=pass_mark else 'status-fail' }}">{{ 'PASS' if r[5]>=pass_mark else 'FAIL' }}</span></td><td>{{ 'Published' if r[7] else 'Hidden' }}</td></tr>{% else %}<tr><td colspan="9">No results have been entered.</td></tr>{% endfor %}</table></div></div><a class="btn" href="{{ url_for('admin_results') }}">Manage results</a>
{% else %}{% for card in cards %}<section class="report-card"><div class="report-heading"><div style="display:flex;align-items:center;justify-content:space-between;gap:12px"><div style="width:70px;height:70px;flex:0 0 70px">{% if settings.get('school_logo_left_url') %}<img src="{{ settings.get('school_logo_left_url') }}" style="width:100%;height:100%;object-fit:contain" alt="School logo">{% endif %}</div><div style="flex:1"><div style="font-weight:800;letter-spacing:1px">{{ settings.get('school_name','Waddilove High School')|upper }}</div><div>{{ settings.get('school_address','') }}</div><h2>STUDENT EXAMINATION REPORT CARD</h2></div><div style="width:70px;height:70px;flex:0 0 70px">{% if settings.get('school_logo_right_url') %}<img src="{{ settings.get('school_logo_right_url') }}" style="width:100%;height:100%;object-fit:contain" alt="School logo">{% endif %}</div></div><strong>{{ card.exam }} · {{ card.term }}</strong></div><div class="grid"><div><b>Student:</b> {{ card.student }}</div><div><b>Student number:</b> {{ card.number }}</div><div><b>Pass mark:</b> {{ pass_mark }}%</div></div><div class="table-wrap"><table><tr><th>Subject</th><th>Mark (%)</th><th>Grade</th><th>Status</th></tr>{% for r in card.subjects %}<tr><td>{{ r[4] }}</td><td>{{ '%.2f'|format(r[5]) }}</td><td>{{ r[6] or '—' }}</td><td><span class="status-pill {{ 'status-pass' if r[5]>=pass_mark else 'status-fail' }}">{{ 'PASS' if r[5]>=pass_mark else 'FAIL' }}</span></td></tr>{% endfor %}</table></div><div class="report-summary"><div><span class="muted">Subjects recorded</span><strong>{{ card.subjects|length }}</strong></div><div><span class="muted">Total marks</span><strong>{{ '%.2f'|format(card.total) }}</strong></div><div><span class="muted">Average</span><strong>{{ '%.2f'|format(card.average) }}%</strong></div><div><span class="muted">Overall status</span><strong><span class="status-pill {{ 'status-pass' if card.overall=='PASS' else 'status-fail' }}">{{ card.overall }}</span></strong></div></div><p class="muted">Overall status is calculated from the average of the subjects shown on this report card.</p><div class="no-print"><button onclick="window.print()">Print report card</button></div></section>{% else %}<div class="card"><h2>No published report cards yet</h2><p>Your end-of-term report card will appear here after the school publishes your results.</p></div>{% endfor %}{% endif %}''',rows=rows,cards=cards,pass_mark=pass_mark)
@app.route('/clubs')
def clubs():
    with connect() as conn:
        with conn.cursor() as c: c.execute('SELECT cl.name,cl.description,cl.leader,m.image_url FROM portal_clubs cl LEFT JOIN portal_media m ON m.id=cl.media_id WHERE cl.active=TRUE ORDER BY cl.name'); rows=c.fetchall()
    return page('Clubs',r'''<div class="hero"><h1>Clubs and societies</h1></div><div class="grid">{% for r in rows %}<div class="card">{% if r[3] %}<img class="media" src="{{ r[3] }}" alt="">{% endif %}<h2>{{ r[0] }}</h2><p>{{ r[1] }}</p><div class="muted">{{ r[2] }}</div></div>{% else %}<div class="card">Club information will appear here soon.</div>{% endfor %}</div>''',rows=rows)
@app.route('/gallery')
def gallery():
    rows=media_rows()
    return page('Gallery',r'''<div class="hero"><h1>School gallery</h1><p>Sports, clubs, school life, events and achievements.</p></div><div class="grid">{% for r in rows if r[2] in ['gallery','club','hero'] %}<div class="card"><a href="{{ r[3] }}" target="_blank" rel="noopener"><img class="media" style="height:180px;object-fit:contain;background:#f5f7fb;padding:8px" src="{{ r[3] }}" alt="{{ r[5] or r[1] }}"></a><h3>{{ r[1] }}</h3><p class="muted">{{ r[2] }}</p><a href="{{ r[3] }}" download>Open/download image</a></div>{% else %}<div class="card">The gallery is waiting for its first photographs.</div>{% endfor %}</div>''',rows=rows)
@app.route('/admin')
@admin_required
def admin():
    counts=[]
    with connect() as conn:
        with conn.cursor() as c:
            for label,table in [('Students','students'),('Student accounts','portal_accounts'),('End-of-term results','portal_exam_results'),('Clubs','portal_clubs'),('Images','portal_media')]:
                c.execute(f'SELECT COUNT(*) FROM {table}'); counts.append((label,c.fetchone()[0]))
            c.execute('SELECT actor,action,details,created_at FROM portal_audit ORDER BY id DESC LIMIT 12'); logs=c.fetchall()
    return page('Admin',r'''<div class="hero"><h1>Admin control centre</h1><p>Manage students, credentials, end-of-term results, clubs and local image uploads.</p></div><div class="grid">{% for x in counts %}<div class="card"><div class="muted">{{ x[0] }}</div><div class="stat">{{ x[1] }}</div></div>{% endfor %}</div><div class="grid">{% for label,endpoint,desc in [('Students and credentials','admin_students','Create students, generate passwords and print slips'),('Results','admin_results','Enter end-of-term marks and publish'),('Images and gallery','admin_media','Upload pictures from this computer'),('Clubs','admin_clubs','Manage clubs and societies'),('Website settings','admin_settings','School name, contact details and homepage'),('Staff/admin accounts','admin_accounts','Create staff/admin logins'),('Audit log','admin_audit','Recent administrative activity')] %}<div class="card"><h2>{{ label }}</h2><p>{{ desc }}</p><a class="btn" href="{{ url_for(endpoint) }}">Open</a></div>{% endfor %}</div><div class="card"><h2>Recent activity</h2><div class="table-wrap"><table><tr><th>Time</th><th>User</th><th>Action</th><th>Details</th></tr>{% for l in logs %}<tr>{% for v in l %}<td>{{ v }}</td>{% endfor %}</tr>{% endfor %}</table></div></div>''',counts=counts,logs=logs)
@app.route('/admin/students',methods=['GET','POST'])
@admin_required
def admin_students():
    new_credentials=[]
    if request.method=='POST':
        action=request.form.get('action')
        try:
            with connect() as conn:
                with conn.cursor() as c:
                    if action=='create':
                        number=request.form.get('student_number','').strip(); name=request.form.get('full_name','').strip(); class_id=request.form.get('class_id','').strip() or None
                        if not number or not name: raise ValueError('Student number and full name are required.')
                        c.execute('SELECT id FROM public.students WHERE student_number=%s OR LOWER(TRIM(full_name))=LOWER(TRIM(%s))',(number,name))
                        if c.fetchone(): raise ValueError('That student number or full name already exists. Student usernames must be unique.')
                        # The existing students table has the exact columns listed in your schema.
                        c.execute("INSERT INTO public.students(student_number,full_name,class_id,guardian,contact,notes,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                            (number,name,class_id,request.form.get('guardian','').strip(),request.form.get('contact','').strip(),request.form.get('notes','').strip(),datetime.now(timezone.utc).isoformat()))
                        sid=c.fetchone()[0]; password=random_password(); c.execute("INSERT INTO portal_accounts(username,full_name,password_hash,role,student_id) VALUES(%s,%s,%s,'student',%s)",(name,name,generate_password_hash(password),sid))
                        new_credentials=[{'name':name,'number':number,'username':name,'password':password}]
                        audit('student_created',f'{number} {name}')
                    elif action=='reset':
                        sid=int(request.form['student_id']); password=random_password()
                        c.execute('SELECT student_number,full_name FROM public.students WHERE id=%s',(sid,)); student=c.fetchone()
                        if not student: raise ValueError('Student record was not found.')
                        c.execute("UPDATE portal_accounts SET password_hash=%s,active=TRUE WHERE student_id=%s RETURNING username,full_name",(generate_password_hash(password),sid)); account=c.fetchone()
                        if not account:
                            c.execute('SELECT id FROM portal_accounts WHERE username=%s',(student[1],))
                            if c.fetchone(): raise ValueError('An account already uses this full name. Resolve the duplicate username before linking this student.')
                            c.execute("INSERT INTO portal_accounts(username,full_name,password_hash,role,student_id) VALUES(%s,%s,%s,'student',%s) RETURNING username,full_name",(student[1],student[1],generate_password_hash(password),sid)); account=c.fetchone()
                        new_credentials=[{'name':account[1],'number':student[0],'username':account[0],'password':password}]; audit('student_password_reset_or_created',str(sid))
                    elif action=='toggle':
                        c.execute('UPDATE portal_accounts SET active=NOT active WHERE student_id=%s RETURNING active',(request.form['student_id'],)); result=c.fetchone()
                        if not result: raise ValueError('No account exists for that student.')
                        audit('student_account_status',f"student={request.form['student_id']} active={result[0]}")
                    elif action=='delete':
                        sid=int(request.form['student_id']); c.execute('DELETE FROM public.students WHERE id=%s',(sid,)); audit('student_deleted',str(sid))
            if new_credentials:
                return page('Print student credentials',r'''<div class="hero no-print"><h1>Student credentials created</h1><p>Print this page now. Passwords are stored only as hashes and cannot be retrieved later.</p><button onclick="window.print()">Print credential slip</button> <a class="btn light" href="{{ url_for('admin_students') }}">Back to students</a></div>{% for x in credentials %}<div class="credential"><h3>{{ settings.get('school_name','Waddilove High School') }} · Student login slip</h3><p><b>Student:</b> {{ x.name }}</p><p><b>Student number:</b> {{ x.number }}</p><p><b>Username:</b> {{ x.username }}</p><p><b>Password:</b> <span style="font-size:20px;font-weight:800">{{ x.password }}</span></p><p>Keep this slip private. Change or reset the password if it is lost.</p></div>{% endfor %}''',credentials=new_credentials)
            flash('Student operation completed.')
        except Exception as e:
            flash(str(e) if isinstance(e,ValueError) else 'Could not complete student operation. Check the database schema and duplicate values.','error')
        return redirect(url_for('admin_students'))
    with connect() as conn:
        with conn.cursor() as c:
            c.execute('SELECT id,student_number,full_name,class_id,guardian,contact FROM public.students ORDER BY full_name'); rows=c.fetchall()
            c.execute('SELECT student_id,username,active FROM portal_accounts WHERE role=\'student\''); accounts={r[0]:r[1:] for r in c.fetchall()}
    return page('Students',r'''<div class="hero"><h1>Students and credentials</h1><p>Student usernames are their full names. Passwords are generated automatically and printed once when created or reset.</p></div><div class="card"><h2>Add student</h2><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="create"><div class="grid"><div><label>Student number</label><input name="student_number" required></div><div><label>Full name (login username)</label><input name="full_name" required></div><div><label>Class ID (optional)</label><input type="number" name="class_id" min="1"></div><div><label>Guardian name (optional)</label><input name="guardian"></div><div><label>Contact (optional)</label><input name="contact"></div><div><label>Notes (optional)</label><input name="notes"></div></div><button>Create student and print credentials</button></form></div><div class="card"><h2>Student list</h2><div class="table-wrap"><table><tr><th>Number</th><th>Full name</th><th>Class ID</th><th>Username/status</th><th>Actions</th></tr>{% for r in rows %}<tr><td>{{ r[1] }}</td><td>{{ r[2] }}</td><td>{{ r[3] or '' }}</td><td>{{ accounts.get(r[0],('',False))[0] }}<br><span class="pill">{{ 'Active' if accounts.get(r[0],('',False))[1] else 'No account/inactive' }}</span></td><td><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="reset"><input type="hidden" name="student_id" value="{{ r[0] }}"><button>Create/reset password & print</button></form><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="toggle"><input type="hidden" name="student_id" value="{{ r[0] }}"><button class="light">Toggle login</button></form></td></tr>{% endfor %}</table></div></div>''',rows=rows,accounts=accounts)
@app.route('/admin/results',methods=['GET','POST'])
@admin_required
def admin_results():
    if request.method=='POST':
        try:
            with connect() as conn:
                with conn.cursor() as c:
                    action=request.form.get('action')
                    if action=='save':
                        sid=int(request.form['student_id']); exam=request.form['exam_name'].strip(); term=request.form['term'].strip(); subject=request.form['subject'].strip(); score=float(request.form['score']); grade=''; pub=request.form.get('published')=='yes'
                        if not exam or not term or not subject or not 0<=score<=100: raise ValueError('Enter exam, term, subject and a score from 0 to 100.')
                        c.execute("INSERT INTO portal_exam_results(student_id,exam_name,term,subject,score,grade,published,result_type) VALUES(%s,%s,%s,%s,%s,%s,%s,'End-of-term') ON CONFLICT(student_id,exam_name,term,subject) DO UPDATE SET score=EXCLUDED.score,grade=EXCLUDED.grade,published=EXCLUDED.published",(sid,exam,term,subject,score,grade,pub)); audit('end_term_result_saved',f'student={sid} subject={subject} published={pub}')
                    elif action=='toggle': c.execute('UPDATE portal_exam_results SET published=NOT published WHERE id=%s',(request.form['id'],)); audit('result_publish_toggled',request.form['id'])
                    elif action=='delete': c.execute('DELETE FROM portal_exam_results WHERE id=%s',(request.form['id'],)); audit('result_deleted',request.form['id'])
            flash('Result operation completed.')
        except Exception as e: flash(str(e) if isinstance(e,ValueError) else 'Could not save result. Check that the selected student exists.','error')
        return redirect(url_for('admin_results'))
    with connect() as conn:
        with conn.cursor() as c:
            c.execute('SELECT id,student_number,full_name FROM public.students ORDER BY full_name'); students=c.fetchall()
            c.execute('SELECT r.id,s.student_number,s.full_name,r.exam_name,r.term,r.subject,r.score,r.grade,r.published FROM portal_exam_results r JOIN public.students s ON s.id=r.student_id ORDER BY r.id DESC LIMIT 1000'); rows=c.fetchall()
    try: pass_mark=float(get_settings().get('pass_mark','50'))
    except (TypeError,ValueError): pass_mark=50.0
    return page('Results',r'''<div class="hero"><h1>End-of-term examination results</h1><p>Only end-of-term exam results belong here. Results are private until published.</p></div><div class="card"><h2>Add or update result</h2><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="save"><label>Student</label><select name="student_id" required>{% for s in students %}<option value="{{ s[0] }}">{{ s[2] }} · {{ s[1] }}</option>{% endfor %}</select><div class="grid"><div><label>Exam name</label><input name="exam_name" placeholder="End of Term 2 Exams" required></div><div><label>Term</label><select name="term" required><option value="Term 1">Term 1</option><option value="Term 2">Term 2</option><option value="Term 3">Term 3</option></select></div><div><label>Subject</label><input name="subject" required></div><div><label>Score (0-100)</label><input type="number" name="score" min="0" max="100" step="0.01" required></div><div><label>Pass/fail</label><input value="Calculated automatically from the pass mark" disabled></div><div><label>Publish result?</label><select name="published"><option value="no">No, keep private</option><option value="yes">Yes, publish</option></select></div></div><button>Save result</button></form></div><div class="card"><h2>Saved results</h2><div class="table-wrap"><table><tr><th>Student</th><th>Exam</th><th>Term</th><th>Subject</th><th>Score</th><th>Pass/fail</th><th>Publication/actions</th></tr>{% for r in rows %}<tr><td>{{ r[2] }}<div class="muted">{{ r[1] }}</div></td><td>{{ r[3] }}</td><td>{{ r[4] }}</td><td>{{ r[5] }}</td><td>{{ r[6] }}%</td><td><span class="status-pill {{ 'status-pass' if r[6]>=pass_mark else 'status-fail' }}">{{ 'PASS' if r[6]>=pass_mark else 'FAIL' }}</span></td><td>{{ 'Published' if r[8] else 'Hidden' }}<form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="toggle"><input type="hidden" name="id" value="{{ r[0] }}"><button class="light">Toggle publish</button></form><form method="post" onsubmit="return confirm('Delete this result?')"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="{{ r[0] }}"><button class="danger">Delete</button></form></td></tr>{% endfor %}</table></div></div>''',students=students,rows=rows,pass_mark=pass_mark)
@app.route('/admin/media',methods=['GET','POST'])
@admin_required
def admin_media():
    if request.method=='POST':
        try:
            action=request.form.get('action')
            if action=='upload':
                f=request.files.get('image'); cat=request.form.get('category','gallery'); title=request.form.get('title','').strip() or secure_filename((f.filename if f else '') or '')
                if cat not in {'left_logo','right_logo','hero','homepage_bg','gallery','club','partner','sports'} or not f or not f.filename: raise ValueError('Choose an image file from this computer and a valid category.')
                path,url=upload_image(f)
                with connect() as conn:
                    with conn.cursor() as c:
                        c.execute('INSERT INTO portal_media(title,category,image_url,storage_path,alt_text) VALUES(%s,%s,%s,%s,%s)',(title,cat,url,path,request.form.get('alt_text','').strip()))
                        if cat in ('left_logo','right_logo','homepage_bg','hero'):
                            key={'left_logo':'school_logo_left_url','right_logo':'school_logo_right_url','homepage_bg':'homepage_background_url','hero':'homepage_background_url'}[cat]
                            c.execute('INSERT INTO portal_settings(setting_key,setting_value) VALUES(%s,%s) ON CONFLICT(setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value',(key,url))
                audit('image_uploaded',f'{cat}: {title}'); flash('Image uploaded. Logos appear beside the school name; the homepage background fills the home-page hero area.')
         ```python
        elif action == 'delete':
            with connect() as conn:
                with conn.cursor() as c:
                    c.execute(
                        'SELECT storage_path, title, category, image_url '
                        'FROM portal_media WHERE id=%s',
                        (request.form['id'],)
                    )
                    old = c.fetchone()
                    if not old:
                        flash('Image record not found.', 'error')
                        return redirect(url_for('admin_media'))

                    storage_path, title, category, image_url = old

                    # Delete the file from Supabase Storage first.
                    if storage_path and SB_URL and SB_KEY:
                        from urllib.parse import unquote

                        path = storage_path.strip()

                        # Extract the path if a full Storage URL was saved.
                        markers = [
                            f'/storage/v1/object/public/{BUCKET}/',
                            f'/storage/v1/object/{BUCKET}/'
                        ]

                        for marker in markers:
                            if marker in path:
                                path = path.split(marker, 1)[1]
                                break

                        path = unquote(path).lstrip('/')

                        # Avoid including the bucket name twice.
                        if path.startswith(f'{BUCKET}/'):
                            path = path[len(BUCKET) + 1:]

                        if not path or path.startswith('http'):
                            flash(
                                'Invalid image storage path. '
                                'The image record was not deleted.',
                                'error'
                            )
                            return redirect(url_for('admin_media'))

                        url = (
                            f"{SB_URL.rstrip('/')}/storage/v1/object/"
                            f"{quote(BUCKET, safe='')}/"
                            f"{quote(path, safe='/')}"
                        )

                        response = requests.delete(
                            url,
                            headers={
                                'Authorization': f'Bearer {SB_KEY}',
                                'apikey': SB_KEY
                            },
                            timeout=20
                        )

                        if response.status_code not in (200, 204):
                            app.logger.error(
                                'Supabase delete failed: HTTP %s; %s',
                                response.status_code,
                                response.text[:500]
                            )
                            flash(
                                f'Supabase file deletion failed '
                                f'(HTTP {response.status_code}). '
                                'Check Render logs.',
                                'error'
                            )
                            return redirect(url_for('admin_media'))

                    elif storage_path:
                        flash(
                            'Supabase configuration is missing. '
                            'The image record was not deleted.',
                            'error'
                        )
                        return redirect(url_for('admin_media'))

                    # Remove the database record only after Storage succeeds.
                    with connect() as conn:
                        with conn.cursor() as c:
                            c.execute(
                                'DELETE FROM portal_media WHERE id=%s',
                                (request.form['id'],)
                            )

                            if category in (
                                'left_logo',
                                'right_logo',
                                'homepage_bg',
                                'hero'
                            ):
                                key = {
                                    'left_logo': 'school_logo_left_url',
                                    'right_logo': 'school_logo_right_url',
                                    'homepage_bg': 'homepage_background_url',
                                    'hero': 'homepage_background_url'
                                }[category]

                                c.execute(
                                    "UPDATE portal_settings "
                                    "SET setting_value='' "
                                    "WHERE setting_key=%s "
                                    "AND setting_value=%s",
                                    (key, image_url)
                                )

            audit('image_deleted', title)
            flash('Image deleted successfully.')
        except Exception as e: flash(str(e) if isinstance(e,ValueError) else 'Image upload/delete failed. Check the Supabase Storage bucket and key.','error')
        return redirect(url_for('admin_media'))
    return page('Images',r'''<div class="hero"><h1>Images and gallery</h1><p>Select image files stored on this computer. They are uploaded to your Supabase Storage bucket, not entered as URLs.</p></div><div class="card"><form method="post" enctype="multipart/form-data"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="upload"><div class="grid"><div><label>Image title</label><input name="title" placeholder="Sports day 2026"></div><div><label>Category</label><select name="category"><option value="left_logo">School logo (left of name)</option><option value="right_logo">School logo (right of name)</option><option value="homepage_bg">Homepage background picture</option><option value="gallery">Gallery</option><option value="sports">Sports</option><option value="club">Clubs</option><option value="partner">Partner logo</option></select></div><div><label>Alternative text</label><input name="alt_text" placeholder="Describe the picture"></div><div><label>Choose image file (max 8 MB)</label><input type="file" name="image" accept="image/png,image/jpeg,image/webp,image/gif" required></div></div><button>Upload selected image</button></form></div><div class="grid">{% for r in rows %}<div class="card"><a href="{{ r[3] }}" target="_blank" rel="noopener"><img class="media" style="height:180px;object-fit:contain;background:#f5f7fb;padding:8px" src="{{ r[3] }}" alt="{{ r[5] or r[1] }}"></a><h3>{{ r[1] }}</h3><p class="muted">{{ r[2] }}</p><form method="post" onsubmit="return confirm('Delete this image?')"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="{{ r[0] }}"><button class="danger">Delete image</button></form></div>{% else %}<div class="card">No images uploaded yet.</div>{% endfor %}</div>''',rows=media_rows())
@app.route('/admin/clubs',methods=['GET','POST'])
@admin_required
def admin_clubs():
    if request.method=='POST':
        try:
            with connect() as conn:
                with conn.cursor() as c:
                    action=request.form.get('action')
                    if action=='save':
                        cid=request.form.get('id'); vals=(request.form['name'].strip(),request.form.get('description','').strip(),request.form.get('leader','').strip(),request.form.get('active')=='yes')
                        if cid: c.execute('UPDATE portal_clubs SET name=%s,description=%s,leader=%s,active=%s WHERE id=%s',(*vals,cid))
                        else: c.execute('INSERT INTO portal_clubs(name,description,leader,active) VALUES(%s,%s,%s,%s)',vals)
                    else: c.execute('DELETE FROM portal_clubs WHERE id=%s',(request.form['id'],))
            flash('Club operation completed.')
        except Exception: flash('Could not save club. Check for duplicate names.','error')
        return redirect(url_for('admin_clubs'))
    with connect() as conn:
        with conn.cursor() as c: c.execute('SELECT id,name,description,leader,active FROM portal_clubs ORDER BY name'); rows=c.fetchall()
    return page('Clubs',r'''<div class="hero"><h1>Clubs and societies</h1></div><div class="card"><h2>Add club</h2><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="save"><label>Name</label><input name="name" required><label>Leader</label><input name="leader"><label>Description</label><textarea name="description"></textarea><label>Visibility</label><select name="active"><option value="yes">Visible</option><option value="no">Hidden</option></select><button>Save club</button></form></div><div class="grid">{% for r in rows %}<div class="card"><h3>{{ r[1] }}</h3><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="save"><input type="hidden" name="id" value="{{ r[0] }}"><label>Name</label><input name="name" value="{{ r[1] }}" required><label>Leader</label><input name="leader" value="{{ r[3] }}"><label>Description</label><textarea name="description">{{ r[2] }}</textarea><label>Visibility</label><select name="active"><option value="yes" {{ 'selected' if r[4] else '' }}>Visible</option><option value="no" {{ 'selected' if not r[4] else '' }}>Hidden</option></select><button>Save changes</button></form><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="{{ r[0] }}"><button class="danger">Delete</button></form></div>{% endfor %}</div>''',rows=rows)
@app.route('/admin/accounts',methods=['GET','POST'])
@admin_required
def admin_accounts():
    if request.method=='POST':
        try:
            username=request.form['username'].strip(); name=request.form['full_name'].strip(); role=request.form['role']; password=request.form['password']
            if role not in ('admin','staff') or len(password)<12: raise ValueError('Choose admin/staff and use a password of at least 12 characters.')
            with connect() as conn:
                with conn.cursor() as c: c.execute('INSERT INTO portal_accounts(username,full_name,password_hash,role) VALUES(%s,%s,%s,%s)',(username,name,generate_password_hash(password),role))
            audit('account_created',f'{username}:{role}'); flash('Account created.')
        except Exception as e: flash(str(e) if isinstance(e,ValueError) else 'Could not create account. Username may already exist.','error')
        return redirect(url_for('admin_accounts'))
    with connect() as conn:
        with conn.cursor() as c: c.execute('SELECT id,username,full_name,role,active FROM portal_accounts WHERE role IN (\'admin\',\'staff\') ORDER BY id'); rows=c.fetchall()
    return page('Staff accounts',r'''<div class="hero"><h1>Staff and admin accounts</h1><p>Use separate accounts for authorised staff. Only admins can manage portal configuration.</p></div><div class="card"><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><div class="grid"><div><label>Username</label><input name="username" required></div><div><label>Full name</label><input name="full_name" required></div><div><label>Role</label><select name="role"><option value="staff">Staff</option><option value="admin">Admin</option></select></div><div><label>Password (12+ characters)</label><input type="password" name="password" minlength="12" required></div></div><button>Create account</button></form></div><div class="card"><table><tr><th>Username</th><th>Name</th><th>Role</th><th>Status</th></tr>{% for r in rows %}<tr>{% for v in r[1:] %}<td>{{ v }}</td>{% endfor %}</tr>{% endfor %}</table></div>''',rows=rows)
@app.route('/admin/settings',methods=['GET','POST'])
@admin_required
def admin_settings():
    keys=['school_name','school_motto','school_address','school_phone','school_email','homepage_intro','results_notice','pass_mark']
    if request.method=='POST':
        with connect() as conn:
            with conn.cursor() as c:
                for k in keys:
                    value=request.form.get(k,'').strip()
                    if k=='pass_mark':
                        try: number=float(value)
                        except ValueError: raise ValueError('Pass mark must be a number from 0 to 100.')
                        if not 0<=number<=100: raise ValueError('Pass mark must be between 0 and 100.')
                        value=str(number)
                    c.execute('INSERT INTO portal_settings(setting_key,setting_value) VALUES(%s,%s) ON CONFLICT(setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value',(k,value))
        audit('settings_updated',','.join(keys)); flash('Settings saved.'); return redirect(url_for('admin_settings'))
    values=get_settings()
    return page('Settings',r'''<div class="hero"><h1>Website settings</h1></div><div class="card"><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}">{% for k,label in fields %}<label>{{ label }}</label>{% if k in ['homepage_intro','results_notice'] %}<textarea name="{{ k }}">{{ values.get(k,'') }}</textarea>{% else %}<input name="{{ k }}" value="{{ values.get(k,'') }}" {% if k=='pass_mark' %}type="number" min="0" max="100" step="0.01" required{% endif %}>{% endif %}{% endfor %}<button>Save settings</button></form></div>''',fields=[('school_name','School name'),('school_motto','School motto'),('school_address','School address'),('school_phone','School phone'),('school_email','School email'),('homepage_intro','Homepage introduction'),('results_notice','Results notice'),('pass_mark','Pass mark percentage (0–100)')],values=values)
@app.route('/admin/audit')
@admin_required
def admin_audit():
    with connect() as conn:
        with conn.cursor() as c: c.execute('SELECT actor,action,details,ip_address,created_at FROM portal_audit ORDER BY id DESC LIMIT 500'); rows=c.fetchall()
    return page('Audit log',r'''<div class="hero"><h1>Audit log</h1></div><div class="card"><div class="table-wrap"><table><tr><th>User</th><th>Action</th><th>Details</th><th>IP</th><th>Time</th></tr>{% for r in rows %}<tr>{% for v in r %}<td>{{ v }}</td>{% endfor %}</tr>{% endfor %}</table></div></div>''',rows=rows)
@app.route('/health')
def health():
    try:
        with connect() as conn:
            with conn.cursor() as c: c.execute('SELECT 1'); c.fetchone()
        return {'status':'ok','database':'connected'}
    except Exception: return {'status':'error','database':'unavailable'},503
if __name__=='__main__':
    init_db()
    app.run(host='127.0.0.1',port=int(os.getenv('PORT','5000')),debug=False)

