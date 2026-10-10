import "dotenv/config";
import express from "express";
import pg from "pg";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import helmet from "helmet";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";

const { Pool } = pg;
const app = express();
const port = Number(process.env.PORT || 3000);
app.disable("x-powered-by"); app.set("trust proxy", 1);
const isProduction = process.env.NODE_ENV === "production";
app.use(helmet({
  contentSecurityPolicy: {
    reportOnly: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: isProduction ? [] : null
    }
  },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));
if(process.env.NODE_ENV==="production" && !process.env.SESSION_SECRET) throw new Error("SESSION_SECRET is required in production");
app.use((req,res,next)=>{
  if(process.env.NODE_ENV==="production" && req.headers["x-forwarded-proto"]!=="https") return res.redirect(308,"https://"+req.get("host")+req.originalUrl);
  res.setHeader("X-Content-Type-Options","nosniff");res.setHeader("X-Frame-Options","DENY");res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");res.setHeader("Permissions-Policy","camera=(self), geolocation=(self), microphone=()");
  if(process.env.NODE_ENV==="production") res.setHeader("Strict-Transport-Security","max-age=31536000; includeSubDomains");
  next()
});
const fallbackRateBuckets=new Map();
function rateLimit({windowMs=60000,max=120,keyPrefix="global"}={}){return async(req,res,next)=>{try{
  const key=keyPrefix+":"+req.ip;
  if(pool){
    const q=await pool.query(`INSERT INTO rate_limit_buckets(bucket_key,window_started,count) VALUES($1,NOW(),1)
      ON CONFLICT(bucket_key) DO UPDATE SET
      count=CASE WHEN rate_limit_buckets.window_started <= NOW() - ($2::bigint * INTERVAL '1 millisecond') THEN 1 ELSE rate_limit_buckets.count+1 END,
      window_started=CASE WHEN rate_limit_buckets.window_started <= NOW() - ($2::bigint * INTERVAL '1 millisecond') THEN NOW() ELSE rate_limit_buckets.window_started END
      RETURNING count`,[key,windowMs]);
    if(Number(q.rows[0].count)>max)return res.status(429).json({error:"Too many requests",message:"Please wait a moment and try again."});
    return next();
  }
  if(isProduction)return res.status(503).json({error:"Rate limiter unavailable"});
  const now=Date.now(),b=fallbackRateBuckets.get(key);
  if(!b||now-b.started>windowMs){fallbackRateBuckets.set(key,{started:now,count:1});return next()}
  b.count++;if(b.count>max)return res.status(429).json({error:"Too many requests",message:"Please wait a moment and try again."});next()
}catch(e){next(e)}}}
const ALLOWED_ORIGINS=new Set(["https://instant-wjihasssodpr-angadphuket345-140e.wix-site-host.com","http://localhost:3000","http://localhost:5173"]);
app.use((req,res,next)=>{const origin=req.headers.origin;if(origin&&ALLOWED_ORIGINS.has(origin)){res.setHeader("Access-Control-Allow-Origin",origin);res.setHeader("Vary","Origin");res.setHeader("Access-Control-Allow-Headers","Content-Type, X-CSRF-Token");res.setHeader("Access-Control-Allow-Methods","GET,POST,PATCH,DELETE,OPTIONS")}if(req.method==="OPTIONS")return res.sendStatus(204);next()});
app.use(express.json({limit:"8mb", strict:true, type:["application/json","application/*+json"]}));
app.use(express.static("public",{setHeaders:(res,path)=>{if(path.endsWith(".html"))res.setHeader("Cache-Control","no-cache");else res.setHeader("Cache-Control","public,max-age=86400")}}));
const pool=process.env.DATABASE_URL?new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL_MODE==="disable"?false:(process.env.PGSSL_CA?{ca:process.env.PGSSL_CA,rejectUnauthorized:true}:process.env.NODE_ENV==="production"?{rejectUnauthorized:true}:undefined)}):null;
const SESSION_SECRET=process.env.SESSION_SECRET;
if(!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error("SESSION_SECRET must be configured with at least 32 characters.");
if(isProduction && !pool) throw new Error("DATABASE_URL is required in production.");
const PgSession=connectPgSimple(session);
if(pool) app.use(session({name:"dd.sid",secret:SESSION_SECRET,store:new PgSession({pool,tableName:"user_sessions",createTableIfMissing:true,pruneSessionInterval:15*60}),resave:false,saveUninitialized:false,rolling:true,cookie:{httpOnly:true,secure:isProduction,sameSite:"lax",maxAge:8*60*60*1000,path:"/"}}));
app.use("/api",rateLimit({windowMs:60000,max:180,keyPrefix:"api"}));
function requireAuth(req,res,next){if(!req.session?.user)return res.status(401).json({error:"Unauthorized",message:"Please sign in again."});req.user=req.session.user;next()}
function boundedString(value,max,{required=false}={}){if(value===null||value===undefined)return !required;if(typeof value!=="string")return false;const v=value.trim();return (required?v.length>0:true)&&v.length<=max}
function validEmail(value){return typeof value==="string"&&value.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)}
function validCoordinate(value,min,max){return value===null||value===undefined||value===""||(typeof value==="number"&&Number.isFinite(value)&&value>=min&&value<=max)}
function validUuid(value){return typeof value==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)}
function validDate(value){if(typeof value!=="string"||!/^\d{4}-\d{2}-\d{2}$/.test(value))return false;const d=new Date(value+"T00:00:00Z");return Number.isFinite(d.getTime())&&d.toISOString().slice(0,10)===value}
function validTime(value){return typeof value==="string"&&/^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$/.test(value)}
function validDaysOfWeek(value){return Array.isArray(value)&&value.length>=1&&value.length<=7&&value.every(d=>Number.isInteger(d)&&d>=1&&d<=7)&&new Set(value).size===value.length}
function validMealType(value){return typeof value==="string"&&["Breakfast","Lunch","Dinner"].includes(value)}
const SAFE_METHODS=new Set(["GET","HEAD","OPTIONS"]);
app.get("/api/csrf",(req,res)=>{if(!req.session)return res.status(503).json({error:"Database unavailable"});if(!req.session.csrfToken)req.session.csrfToken=crypto.randomBytes(32).toString("base64url");res.setHeader("Cache-Control","no-store");res.json({csrfToken:req.session.csrfToken})});
app.use("/api",(req,res,next)=>{if(SAFE_METHODS.has(req.method)||req.path==="/csrf"||req.path==="/health"||req.path==="/public-config")return next();const sent=req.get("x-csrf-token"),expected=req.session?.csrfToken;if(!sent||!expected||sent.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(sent),Buffer.from(expected)))return res.status(403).json({error:"CSRF validation failed",message:"Refresh the page and try again."});next()});
function adminOnly(req,res,next){if(req.user?.role!=="admin")return res.status(403).json({error:"Forbidden",message:"Admin access required."});next()}
async function migrate(){if(!pool)return;await pool.query(`CREATE TABLE IF NOT EXISTS rate_limit_buckets (bucket_key TEXT PRIMARY KEY, window_started TIMESTAMPTZ NOT NULL, count INTEGER NOT NULL DEFAULT 0); CREATE INDEX IF NOT EXISTS idx_rate_limit_window ON rate_limit_buckets(window_started); -- Production V1 database schema
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','driver')),
  name TEXT NOT NULL,
  phone TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  on_duty BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS customers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  phone TEXT,
  whatsapp_number TEXT,
  address TEXT NOT NULL,
  area TEXT,
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  delivery_window_start TIME,
  delivery_window_end TIME,
  instructions TEXT,
  tiffin_paused BOOLEAN NOT NULL DEFAULT FALSE,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS recurring_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  driver_id UUID REFERENCES users(id) ON DELETE SET NULL,
  meal_type TEXT NOT NULL DEFAULT 'Lunch',
  delivery_time TIME,
  days_of_week SMALLINT[] NOT NULL DEFAULT ARRAY[1,2,3,4,5,6],
  active BOOLEAN NOT NULL DEFAULT TRUE,
  paused_until DATE,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  delivery_code TEXT UNIQUE NOT NULL,
  customer_id UUID NOT NULL REFERENCES customers(id),
  driver_id UUID REFERENCES users(id) ON DELETE SET NULL,
  recurring_delivery_id UUID REFERENCES recurring_deliveries(id) ON DELETE SET NULL,
  delivery_date DATE NOT NULL,
  planned_time TIME,
  route_order INTEGER,
  status TEXT NOT NULL DEFAULT 'Pending',
  empty_photo_data TEXT,
  empty_photo_at TIMESTAMPTZ,
  empty_latitude DOUBLE PRECISION,
  empty_longitude DOUBLE PRECISION,
  delivery_photo_data TEXT,
  delivery_photo_at TIMESTAMPTZ,
  delivery_latitude DOUBLE PRECISION,
  delivery_longitude DOUBLE PRECISION,
  delivered_at TIMESTAMPTZ,
  meal_type TEXT NOT NULL DEFAULT 'Lunch',
  whatsapp_status TEXT,
  whatsapp_message_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(customer_id, delivery_date, meal_type)
);
CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS leaves (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  leave_date DATE NOT NULL,
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, leave_date)
);
CREATE INDEX IF NOT EXISTS idx_deliveries_date_driver ON deliveries(delivery_date, driver_id);
CREATE INDEX IF NOT EXISTS idx_recurring_active ON recurring_deliveries(active);
CREATE INDEX IF NOT EXISTS idx_customers_active ON customers(active);
`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT, ADD COLUMN IF NOT EXISTS on_duty BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique ON users(LOWER(email)) WHERE email IS NOT NULL AND email <> ''`);
  await pool.query(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS cycle_days SMALLINT CHECK (cycle_days IN (7,15,30)), ADD COLUMN IF NOT EXISTS cycle_started_at DATE`);
  await pool.query(`CREATE TABLE IF NOT EXISTS password_reset_requests (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, otp_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, attempts SMALLINT NOT NULL DEFAULT 0, consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE INDEX IF NOT EXISTS password_reset_user_active_idx ON password_reset_requests(user_id, expires_at DESC) WHERE consumed_at IS NULL`);
  await pool.query(`CREATE TABLE IF NOT EXISTS admin_notifications (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), event_type TEXT NOT NULL, message TEXT NOT NULL, actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), read_at TIMESTAMPTZ)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS admin_notifications_created_idx ON admin_notifications(created_at DESC)`);
  await pool.query(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS whatsapp_number TEXT, ADD COLUMN IF NOT EXISTS address TEXT, ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION, ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION, ADD COLUMN IF NOT EXISTS delivery_window_start TIME, ADD COLUMN IF NOT EXISTS delivery_window_end TIME, ADD COLUMN IF NOT EXISTS instructions TEXT, ADD COLUMN IF NOT EXISTS tiffin_paused BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS recurring_delivery_id UUID, ADD COLUMN IF NOT EXISTS route_order INTEGER, ADD COLUMN IF NOT EXISTS meal_type TEXT NOT NULL DEFAULT 'Lunch', ADD COLUMN IF NOT EXISTS whatsapp_message_id TEXT`);
  await pool.query(`ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS meal_type TEXT NOT NULL DEFAULT 'Lunch'`);
  await pool.query(`ALTER TABLE deliveries DROP CONSTRAINT IF EXISTS deliveries_customer_id_delivery_date_key`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS deliveries_customer_date_meal_key ON deliveries(customer_id, delivery_date, meal_type)`);
  await pool.query("DELETE FROM rate_limit_buckets WHERE window_started < NOW() - INTERVAL '1 day'");
}
async function seedDemoAccounts(){
  if(process.env.DEMO_ACCOUNTS_ENABLED!=="true") return;
  const accounts=[
    {key:"admin",username:process.env.DEMO_ADMIN_USERNAME,password:process.env.DEMO_ADMIN_PASSWORD,role:"admin",name:process.env.DEMO_ADMIN_NAME||"Demo Manager"},
    {key:"driver",username:process.env.DEMO_DRIVER_USERNAME,password:process.env.DEMO_DRIVER_PASSWORD,role:"driver",name:process.env.DEMO_DRIVER_NAME||"Demo Driver"}
  ];
  for(const account of accounts){
    if(typeof account.username!=="string"||!/^[a-z0-9._-]{3,80}$/.test(account.username)||
       typeof account.password!=="string"||account.password.length<12||account.password.length>200||
       typeof account.name!=="string"||!account.name.trim()||account.name.length>120){
      throw new Error("Demo account configuration is incomplete or invalid. Set valid demo usernames and passwords (12–200 characters).");
    }
  }
  if(accounts[0].username===accounts[1].username) throw new Error("Demo admin and driver usernames must be different.");
  for(const account of accounts){
    const existing=await pool.query("SELECT id,role FROM users WHERE username=$1 LIMIT 1",[account.username]);
    if(existing.rows[0]){
      if(existing.rows[0].role!==account.role) throw new Error("Configured demo username already exists with a different role: "+account.username);
      console.log("Demo account already exists; leaving its password and profile unchanged:",account.username);
      continue;
    }
    const passwordHash=await bcrypt.hash(account.password,12);
    const inserted=await pool.query(
      "INSERT INTO users(username,password_hash,role,name,active,on_duty) VALUES($1,$2,$3,$4,TRUE,FALSE) ON CONFLICT(username) DO NOTHING RETURNING id",
      [account.username,passwordHash,account.role,account.name.trim()]
    );
    if(!inserted.rows[0]){
      const raced=await pool.query("SELECT role FROM users WHERE username=$1 LIMIT 1",[account.username]);
      if(raced.rows[0]?.role!==account.role) throw new Error("Configured demo username was concurrently created with a different role: "+account.username);
    }else{
      console.log("Created configured demo account:",account.username,"role:",account.role);
    }
  }
}

app.get("/api/public-config",(_req,res)=>res.json({analyticsId:process.env.GA_MEASUREMENT_ID||""}));

async function sendResetEmail(to,subject,text){if(!process.env.RESEND_API_KEY||!process.env.RESET_EMAIL_FROM)throw new Error("Email reset provider is not configured");const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{"Authorization":"Bearer "+process.env.RESEND_API_KEY,"Content-Type":"application/json"},body:JSON.stringify({from:process.env.RESET_EMAIL_FROM,to:[to],subject,text})});if(!r.ok)throw new Error("Email provider rejected the message")}
async function sendResetSms(to,text){const sid=process.env.TWILIO_ACCOUNT_SID,token=process.env.TWILIO_AUTH_TOKEN,from=process.env.TWILIO_FROM_NUMBER;if(!sid||!token||!from)throw new Error("SMS reset provider is not configured");const body=new URLSearchParams({To:to,From:from,Body:text});const r=await fetch("https://api.twilio.com/2010-04-01/Accounts/"+encodeURIComponent(sid)+"/Messages.json",{method:"POST",headers:{"Authorization":"Basic "+Buffer.from(sid+":"+token).toString("base64"),"Content-Type":"application/x-www-form-urlencoded"},body});if(!r.ok)throw new Error("SMS provider rejected the message")}
function resetDigest(userId,otp){return crypto.createHash("sha256").update(userId+":"+otp+":"+SESSION_SECRET).digest("hex")}
app.post("/api/password-reset/request",rateLimit({windowMs:10*60*1000,max:5,keyPrefix:"password-reset"}),async(req,res,next)=>{try{const username=String(req.body?.username||"").trim().toLowerCase();res.setHeader("Cache-Control","no-store");const generic={ok:true,message:"If the account exists and has a configured recovery contact, instructions will be sent shortly."};if(username.length<2||username.length>80)return res.json(generic);const q=await pool.query("SELECT id,role,name,email,phone FROM users WHERE username=$1 AND active=true LIMIT 1",[username]);const u=q.rows[0];if(!u)return res.json(generic);const destination=u.role==="admin"?u.email:u.phone;if(!destination)return res.json(generic);const otp=String(crypto.randomInt(0,1000000)).padStart(6,"0");const configured=u.role==="admin"?Boolean(process.env.RESEND_API_KEY&&process.env.RESET_EMAIL_FROM):Boolean(process.env.TWILIO_ACCOUNT_SID&&process.env.TWILIO_AUTH_TOKEN&&process.env.TWILIO_FROM_NUMBER);if(!configured)return res.json(generic);await pool.query("UPDATE password_reset_requests SET consumed_at=NOW() WHERE user_id=$1 AND consumed_at IS NULL",[u.id]);await pool.query("INSERT INTO password_reset_requests(user_id,otp_hash,expires_at) VALUES($1,$2,NOW()+INTERVAL '10 minutes')",[u.id,resetDigest(u.id,otp)]);try{if(u.role==="admin")await sendResetEmail(u.email,"Dabba Dope password reset","Your password reset code is "+otp+". It expires in 10 minutes. If you did not request this, ignore this email.");else await sendResetSms(u.phone,"Dabba Dope password reset code: "+otp+". Expires in 10 minutes.");}catch(e){await pool.query("UPDATE password_reset_requests SET consumed_at=NOW() WHERE user_id=$1 AND consumed_at IS NULL",[u.id]);throw e}return res.json(generic)}catch(e){next(e)}});
app.post("/api/password-reset/confirm",rateLimit({windowMs:10*60*1000,max:8,keyPrefix:"password-reset-confirm"}),async(req,res,next)=>{try{const username=String(req.body?.username||"").trim().toLowerCase(),otp=String(req.body?.otp||""),password=String(req.body?.newPassword||"");if(!/^\d{6}$/.test(otp)||password.length<12||password.length>200)return res.status(400).json({error:"Invalid reset details",message:"Enter the six-digit code and a password between 12 and 200 characters."});const u=await pool.query("SELECT id,name,role FROM users WHERE username=$1 AND active=true LIMIT 1",[username]);if(!u.rows[0])return res.status(400).json({error:"Invalid or expired code"});const client=await pool.connect();let changed=false;try{await client.query("BEGIN");const q=await client.query("SELECT id,otp_hash,attempts FROM password_reset_requests WHERE user_id=$1 AND consumed_at IS NULL AND expires_at>NOW() ORDER BY created_at DESC LIMIT 1 FOR UPDATE",[u.rows[0].id]);const row=q.rows[0];if(!row||row.attempts>=5||row.otp_hash!==resetDigest(u.rows[0].id,otp)){if(row)await client.query("UPDATE password_reset_requests SET attempts=attempts+1,consumed_at=CASE WHEN attempts+1>=5 THEN NOW() ELSE consumed_at END WHERE id=$1",[row.id]);await client.query("COMMIT");return res.status(400).json({error:"Invalid or expired code"})}await client.query("UPDATE users SET password_hash=$1,updated_at=NOW() WHERE id=$2",[await bcrypt.hash(password,12),u.rows[0].id]);await client.query("DELETE FROM user_sessions WHERE sess->'user'->>'id'=$1",[u.rows[0].id]);await client.query("UPDATE password_reset_requests SET consumed_at=NOW() WHERE id=$1",[row.id]);if(u.rows[0].role==="driver")await client.query("INSERT INTO admin_notifications(event_type,message,actor_user_id) VALUES('driver_password_reset',$1,$2)",["Driver "+u.rows[0].name+" has reset their password on "+new Date().toLocaleString("en-IN",{timeZone:"Asia/Kolkata"}),u.rows[0].id]);await client.query("COMMIT");changed=true}catch(e){await client.query("ROLLBACK");throw e}finally{client.release()}if(changed&&u.rows[0].role==="driver"){try{const admin=await pool.query("SELECT email FROM users WHERE role='admin' AND active=true AND email IS NOT NULL AND email<>'' ORDER BY created_at LIMIT 1");if(admin.rows[0])await sendResetEmail(admin.rows[0].email,"Dabba Dope driver password reset","Driver "+u.rows[0].name+" has reset their password on "+new Date().toLocaleString("en-IN",{timeZone:"Asia/Kolkata"})+".")}catch(e){console.error("Admin password-reset notification delivery failed",{message:e.message})}}res.setHeader("Cache-Control","no-store");res.json({ok:true,message:"Password reset successfully. You can sign in with your new password."})}catch(e){next(e)}});
app.get("/api/admin/notifications",requireAuth,adminOnly,async(req,res,next)=>{try{const q=await pool.query("SELECT id,event_type,message,created_at,read_at FROM admin_notifications ORDER BY created_at DESC LIMIT 50");res.setHeader("Cache-Control","no-store");res.json({notifications:q.rows})}catch(e){next(e)}});
app.post("/api/login",rateLimit({windowMs:10*60*1000,max:12,keyPrefix:"login"}),async(req,res,next)=>{try{if(!pool)return res.status(503).json({error:"Database unavailable"});const username=String(req.body?.username||"").trim().toLowerCase(),password=String(req.body?.password||"");if(username.length<2||username.length>80||password.length<1||password.length>200)return res.status(400).json({error:"Invalid login",message:"Please enter a valid Staff ID and password."});const q=await pool.query("SELECT id,username,password_hash,role,name,email FROM users WHERE username=$1 AND active=true LIMIT 1",[username]);const u=q.rows[0];if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"Invalid credentials",message:"Staff ID or password is incorrect."});const safe={id:u.id,username:u.username,role:u.role,name:u.name,email:u.email||null};req.session.regenerate(err=>{if(err)return next(err);req.session.user=safe;req.session.csrfToken=crypto.randomBytes(32).toString("base64url");req.session.save(err2=>{if(err2)return next(err2);res.setHeader("Cache-Control","no-store");res.json({user:safe,csrfToken:req.session.csrfToken})})})}catch(e){next(e)}});
app.post("/api/profile/password",requireAuth,async(req,res,next)=>{try{const current=String(req.body?.currentPassword||""),nextPw=String(req.body?.newPassword||"");if(nextPw.length<12||nextPw.length>200)return res.status(400).json({error:"Invalid password",message:"New password must be between 12 and 200 characters."});const q=await pool.query("SELECT password_hash FROM users WHERE id=$1 AND active=true",[req.user.id]);if(!q.rows[0]||!(await bcrypt.compare(current,q.rows[0].password_hash)))return res.status(401).json({error:"Invalid credentials",message:"Current password is incorrect."});await pool.query("UPDATE users SET password_hash=$1,updated_at=NOW() WHERE id=$2",[await bcrypt.hash(nextPw,12),req.user.id]);res.json({ok:true})}catch(e){next(e)}});
app.patch("/api/profile/email",requireAuth,async(req,res,next)=>{try{if(req.user.role!=="admin")return res.status(403).json({error:"Forbidden",message:"Only the admin account can set the recovery email here."});const email=String(req.body?.email||"").trim().toLowerCase();const domain=email.split("@")[1]||"";if(email.length>254||!email.includes("@")||!domain.includes(".")||email.includes(" "))return res.status(400).json({error:"Invalid email",message:"Enter a valid recovery email address."});const q=await pool.query("UPDATE users SET email=$1,updated_at=NOW() WHERE id=$2 AND role='admin' RETURNING email",[email,req.user.id]);if(!q.rows[0])return res.status(404).json({error:"Admin account not found"});req.session.user.email=q.rows[0].email;req.session.save(err=>{if(err)return next(err);res.json({ok:true,email:q.rows[0].email})})}catch(e){if(e.code==="23505")return res.status(409).json({error:"Email already in use"});next(e)}});
app.get("/api/me",requireAuth,(req,res)=>{res.setHeader("Cache-Control","no-store");res.json({user:req.user})});
app.post("/api/logout",requireAuth,(req,res,next)=>{req.session.destroy(err=>{if(err)return next(err);res.clearCookie("dd.sid",{path:"/",httpOnly:true,secure:isProduction,sameSite:"lax"});res.setHeader("Cache-Control","no-store");res.json({ok:true})})});
app.get("/api/settings",requireAuth,adminOnly,async(req,res,next)=>{try{const q=await pool.query("SELECT key,value FROM app_settings WHERE key='whatsapp_number'");res.json({settings:{whatsappNumber:q.rows[0]?.value||""}})}catch(e){next(e)}});
app.patch("/api/settings",requireAuth,adminOnly,async(req,res,next)=>{try{const value=String(req.body?.whatsappNumber||"").trim();if(value && !/^\+?[0-9 ()-]{8,20}$/.test(value))return res.status(400).json({error:"Enter a valid WhatsApp number"});await pool.query("INSERT INTO app_settings(key,value,updated_at) VALUES('whatsapp_number',$1,NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()",[value||null]);res.json({ok:true,whatsappNumber:value})}catch(e){next(e)}});
app.get("/api/customers",requireAuth,adminOnly,async(req,res,next)=>{try{const q=await pool.query("SELECT * FROM customers ORDER BY name");res.json({customers:q.rows})}catch(e){next(e)}});
app.post("/api/customers",requireAuth,adminOnly,async(req,res,next)=>{const b=req.body||{},cycleDays=Number(b.cycleDays||7);if(![7,15,30].includes(cycleDays)||!boundedString(b.name,120,{required:true})||!boundedString(b.address,500,{required:true})||!boundedString(b.phone,32)||!boundedString(b.whatsappNumber,32)||!boundedString(b.area,120)||!boundedString(b.instructions,1000)||!validCoordinate(b.latitude,-90,90)||!validCoordinate(b.longitude,-180,180)||((b.latitude!==null&&b.latitude!==undefined&&b.latitude!=="")!==(b.longitude!==null&&b.longitude!==undefined&&b.longitude!=="")))return res.status(400).json({error:"Invalid customer details",message:"Check required name/address, cycle (7, 15, or 30 days), field lengths, and coordinate values."});const client=await pool.connect();try{await client.query("BEGIN");const code=b.customerCode||"C-"+crypto.randomUUID().slice(0,8).toUpperCase();const q=await client.query("INSERT INTO customers(customer_code,name,phone,whatsapp_number,address,area,latitude,longitude,delivery_window_start,delivery_window_end,instructions,cycle_days,cycle_started_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_DATE) RETURNING *",[code,b.name,b.phone||null,b.whatsappNumber||b.phone||null,b.address,b.area||null,b.latitude??null,b.longitude??null,b.deliveryWindowStart||null,b.deliveryWindowEnd||null,b.instructions||null,cycleDays]);const customer=q.rows[0];await client.query("INSERT INTO deliveries(delivery_code,customer_id,delivery_date,planned_time,meal_type,status) SELECT 'DEL-'||upper(substr(md5($1::text||':'||g.day),1,8)),$1,CURRENT_DATE+g.day-1,$2,'Lunch','Pending' FROM generate_series(1,$3::int) AS g(day) ON CONFLICT(customer_id,delivery_date,meal_type) DO NOTHING",[customer.id,b.deliveryWindowStart||null,cycleDays]);await client.query("COMMIT");res.status(201).json({customer,scheduledDays:cycleDays})}catch(e){await client.query("ROLLBACK");if(e.code==="23505")return res.status(409).json({error:"Customer code already exists"});next(e)}finally{client.release()}});
app.patch("/api/customers/:id",requireAuth,adminOnly,async(req,res,next)=>{try{const b=req.body||{};const has=k=>Object.prototype.hasOwnProperty.call(b,k);if((has("name")&&!boundedString(b.name,120,{required:true}))||(has("address")&&!boundedString(b.address,500,{required:true}))||(has("phone")&&!boundedString(b.phone,32))||(has("whatsappNumber")&&!boundedString(b.whatsappNumber,32))||(has("area")&&!boundedString(b.area,120))||(has("instructions")&&!boundedString(b.instructions,1000))||(has("latitude")&&!validCoordinate(b.latitude,-90,90))||(has("longitude")&&!validCoordinate(b.longitude,-180,180))||(has("active")&&typeof b.active!=="boolean")||(has("tiffinPaused")&&typeof b.tiffinPaused!=="boolean"))return res.status(400).json({error:"Invalid customer details",message:"Check field lengths, coordinate ranges, and boolean values."});if((has("latitude")!==has("longitude"))||(has("latitude")&&((b.latitude===null)!==(b.longitude===null))))return res.status(400).json({error:"Invalid customer coordinates",message:"Latitude and longitude must be provided or cleared together."});const q=await pool.query(`UPDATE customers SET name=COALESCE($1,name),phone=COALESCE($2,phone),whatsapp_number=COALESCE($3,whatsapp_number),address=COALESCE($4,address),area=COALESCE($5,area),latitude=CASE WHEN $6::boolean THEN $7 ELSE latitude END,longitude=CASE WHEN $6::boolean THEN $8 ELSE longitude END,active=COALESCE($9,active),tiffin_paused=COALESCE($10,tiffin_paused),instructions=COALESCE($11,instructions),updated_at=NOW() WHERE id=$12 RETURNING *`,[b.name,b.phone,b.whatsappNumber,b.address,b.area,has("latitude"),b.latitude,b.longitude,b.active,b.tiffinPaused,b.instructions,req.params.id]);if(!q.rows[0])return res.status(404).json({error:"Customer not found"});res.json({customer:q.rows[0]})}catch(e){next(e)}});
app.delete("/api/customers/:id",requireAuth,adminOnly,async(req,res,next)=>{try{await pool.query("UPDATE customers SET active=false,updated_at=NOW() WHERE id=$1",[req.params.id]);res.json({ok:true})}catch(e){next(e)}});
app.get("/api/staff",requireAuth,adminOnly,async(req,res,next)=>{try{const q=await pool.query("SELECT id,username,name,phone,email,role,active,on_duty FROM users WHERE role='driver' ORDER BY name");res.json({staff:q.rows})}catch(e){next(e)}});
app.post("/api/staff",requireAuth,adminOnly,async(req,res,next)=>{try{const b=req.body||{};if(!boundedString(b.username,80,{required:true})||!/^[a-zA-Z0-9._-]+$/.test(b.username)||!boundedString(b.name,120,{required:true})||typeof b.password!=="string"||b.password.length<12||b.password.length>200||!boundedString(b.phone,32)||(b.email!=null&&b.email!==""&&!validEmail(b.email)))return res.status(400).json({error:"Invalid staff details",message:"Use a valid staff ID, name, optional email, and password between 12 and 200 characters."});const q=await pool.query("INSERT INTO users(username,password_hash,role,name,phone,email) VALUES($1,$2,'driver',$3,$4,$5) RETURNING id,username,name,phone,email,role,active,on_duty",[b.username.toLowerCase(),await bcrypt.hash(b.password,12),b.name,b.phone||null,(typeof b.email==='string'&&b.email.trim()?b.email.trim().toLowerCase():null)]);res.status(201).json({staff:q.rows[0]})}catch(e){next(e)}});
app.patch("/api/staff/:id",requireAuth,adminOnly,async(req,res,next)=>{try{const b=req.body||{},has=k=>Object.prototype.hasOwnProperty.call(b,k);if((has("name")&&!boundedString(b.name,120,{required:true}))||(has("phone")&&!boundedString(b.phone,32))||(has("active")&&typeof b.active!=="boolean")||(has("onDuty")&&typeof b.onDuty!=="boolean")||(has("email")&&b.email!==null&&b.email!==""&&!validEmail(b.email)))return res.status(400).json({error:"Invalid driver details",message:"Check name, phone, status, and email address."});const q=await pool.query("UPDATE users SET name=COALESCE($1,name),phone=COALESCE($2,phone),email=CASE WHEN $6::boolean THEN $7 ELSE email END,active=COALESCE($3,active),on_duty=COALESCE($4,on_duty),updated_at=NOW() WHERE id=$5 AND role='driver' RETURNING id,username,name,phone,email,role,active,on_duty",[b.name,b.phone,b.active,b.onDuty,req.params.id,has("email"),typeof b.email==="string"&&b.email.trim()?b.email.trim().toLowerCase():null]);if(!q.rows[0])return res.status(404).json({error:"Driver not found"});res.json({staff:q.rows[0]})}catch(e){if(e.code==="23505")return res.status(409).json({error:"Email already in use"});next(e)}});
app.patch("/api/staff/:id/duty",requireAuth,async(req,res,next)=>{try{const id=req.user.role==="driver"?req.user.id:req.params.id;const onDuty=Boolean(req.body?.onDuty);const q=await pool.query("UPDATE users SET on_duty=$1,updated_at=NOW() WHERE id=$2 AND role='driver' RETURNING id,on_duty",[onDuty,id]);if(!q.rows[0])return res.status(404).json({error:"Driver not found"});res.json({staff:q.rows[0]})}catch(e){next(e)}});
app.get("/api/history/report",requireAuth,adminOnly,async(req,res,next)=>{try{const days=Number(req.query.days);if(![7,15,30].includes(days))return res.status(400).json({error:"Invalid report range",message:"Choose 7, 15, or 30 days."});const q=await pool.query("SELECT d.delivery_code code,c.name customer,u.name driver,d.delivery_date,d.delivered_at,d.status,c.area,c.address,d.meal_type,COALESCE(TO_CHAR(d.planned_time,'HH12:MI AM'),'') time FROM deliveries d JOIN customers c ON c.id=d.customer_id LEFT JOIN users u ON u.id=d.driver_id WHERE d.delivery_date >= CURRENT_DATE - ($1::int - 1) AND d.delivery_date <= CURRENT_DATE ORDER BY d.delivery_date DESC,d.planned_time NULLS LAST,c.name",[days]);res.setHeader("Cache-Control","no-store");res.json({days,generatedAt:new Date().toISOString(),deliveries:q.rows})}catch(e){next(e)}});
app.post("/api/deliveries",requireAuth,adminOnly,async(req,res,next)=>{try{const b=req.body||{};if(!validUuid(b.customerId)||!(b.driverId===null||b.driverId===""||validUuid(b.driverId))||!validDate(b.deliveryDate)||!validMealType(b.mealType||"Lunch")||(b.plannedTime&&!validTime(b.plannedTime)))return res.status(400).json({error:"Invalid delivery details",message:"Choose a valid customer, optional driver, date, meal, and time."});const customer=await pool.query("SELECT id FROM customers WHERE id=$1 AND active=true",[b.customerId]);if(!customer.rows[0])return res.status(400).json({error:"Customer unavailable",message:"Choose an active customer."});if(b.driverId){const driver=await pool.query("SELECT id FROM users WHERE id=$1 AND role='driver' AND active=true",[b.driverId]);if(!driver.rows[0])return res.status(400).json({error:"Driver unavailable",message:"Choose an active driver."})}const code="DEL-"+crypto.randomUUID().replaceAll("-","").slice(0,8).toUpperCase();const q=await pool.query("INSERT INTO deliveries(delivery_code,customer_id,driver_id,delivery_date,planned_time,meal_type,status) VALUES($1,$2,$3,$4,$5,$6,'Pending') RETURNING id,delivery_code code,customer_id,driver_id,delivery_date,planned_time,meal_type,status",[code,b.customerId,b.driverId||null,b.deliveryDate,b.plannedTime||null,b.mealType||"Lunch"]);res.status(201).json({delivery:q.rows[0]})}catch(e){if(e.code==="23505")return res.status(409).json({error:"A delivery for this customer, date, and meal already exists."});next(e)}});
app.get("/api/deliveries",requireAuth,async(req,res,next)=>{try{const history=req.query.history==="true";const date=req.query.date||new Date().toISOString().slice(0,10);const params=[];let where;if(history){where="d.status='Delivered'";}else{params.push(date);where="d.delivery_date=$1::date"}if(!history){where+=" AND c.active=TRUE AND c.tiffin_paused=FALSE"}if(req.user.role==="driver"){params.push(req.user.id);where+=" AND d.driver_id=$"+params.length}const q=await pool.query(`SELECT d.id,d.delivery_code code,d.delivery_date,d.meal_type,c.id customer_id,c.name customer,c.phone,c.whatsapp_number,c.address,c.area,c.latitude,c.longitude,u.id driver_id,u.name driver,d.status,d.route_order,COALESCE(TO_CHAR(d.planned_time,'HH12:MI AM'),'') time,d.empty_photo_data IS NOT NULL has_empty_photo,d.delivery_photo_data IS NOT NULL has_delivery_photo,d.whatsapp_status FROM deliveries d JOIN customers c ON c.id=d.customer_id LEFT JOIN users u ON u.id=d.driver_id WHERE ${where} ORDER BY d.delivery_date DESC,d.route_order NULLS LAST,d.planned_time NULLS LAST,c.name`,params);res.json({deliveries:q.rows})}catch(e){next(e)}});
app.post("/api/deliveries/:code/empty-proof",requireAuth,async(req,res,next)=>{try{if(req.user.role!=="driver")return res.status(403).json({error:"Forbidden"});const b=req.body||{};if(typeof b.photo!=="string"||!/^data:image\/(jpeg|jpg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(b.photo)||b.photo.length>6*1024*1024)return res.status(400).json({error:"Invalid delivery proof",message:"Upload a valid JPEG, PNG, or WebP photo under 4.5 MB."});if(!validCoordinate(b.latitude,-90,90)||!validCoordinate(b.longitude,-180,180)||((b.latitude!==null&&b.latitude!==undefined)!==(b.longitude!==null&&b.longitude!==undefined)))return res.status(400).json({error:"Invalid GPS coordinates"});const q=await pool.query("UPDATE deliveries SET status='Empty Tiffin Collected',empty_photo_data=$1,empty_photo_at=NOW(),empty_latitude=$2,empty_longitude=$3,updated_at=NOW() WHERE delivery_code=$4 AND driver_id=$5 AND status IN ('Pending','Planned','Empty Tiffin Collected') RETURNING delivery_code code,status",[b.photo,b.latitude??null,b.longitude??null,req.params.code,req.user.id]);if(!q.rows[0])return res.status(404).json({error:"Delivery not found"});res.json({delivery:q.rows[0]})}catch(e){next(e)}});
app.post("/api/deliveries/:code/complete",requireAuth,async(req,res,next)=>{try{if(req.user.role!=="driver")return res.status(403).json({error:"Forbidden"});const b=req.body||{};if(typeof b.photo!=="string"||!/^data:image\/(jpeg|jpg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(b.photo)||b.photo.length>6*1024*1024)return res.status(400).json({error:"Invalid delivery proof",message:"Upload a valid JPEG, PNG, or WebP photo under 4.5 MB."});if(!validCoordinate(b.latitude,-90,90)||!validCoordinate(b.longitude,-180,180)||((b.latitude!==null&&b.latitude!==undefined)!==(b.longitude!==null&&b.longitude!==undefined)))return res.status(400).json({error:"Invalid GPS coordinates"});const q=await pool.query("UPDATE deliveries SET status='Delivered',delivery_photo_data=$1,delivery_photo_at=NOW(),delivered_at=NOW(),delivery_latitude=$2,delivery_longitude=$3,whatsapp_status='Queued',updated_at=NOW() WHERE delivery_code=$4 AND driver_id=$5 AND empty_photo_data IS NOT NULL AND status IN ('Empty Tiffin Collected','Pending') RETURNING delivery_code code,status,delivered_at,customer_id",[b.photo,b.latitude??null,b.longitude??null,req.params.code,req.user.id]);if(!q.rows[0])return res.status(409).json({error:"Collect the empty-tiffin photo before completing delivery."});res.json({delivery:q.rows[0],whatsapp:"Queued"})}catch(e){next(e)}});
app.get("/api/deliveries/:code/proof",requireAuth,async(req,res,next)=>{try{const q=await pool.query("SELECT d.delivery_code code,c.name customer,u.name driver,d.status,d.empty_photo_data,d.empty_photo_at,d.empty_latitude,d.empty_longitude,d.delivery_photo_data,d.delivery_photo_at,d.delivery_latitude,d.delivery_longitude,d.delivered_at,d.whatsapp_status FROM deliveries d JOIN customers c ON c.id=d.customer_id LEFT JOIN users u ON u.id=d.driver_id WHERE d.delivery_code=$1 AND ($2='admin' OR d.driver_id=$3)",[req.params.code,req.user.role,req.user.id]);if(!q.rows[0])return res.status(404).json({error:"Proof not found"});res.json({proof:q.rows[0]})}catch(e){next(e)}});
function distance(a,b){const R=6371,rad=x=>x*Math.PI/180,dLat=rad(b.lat-a.lat),dLon=rad(b.lon-a.lon),s=Math.sin(dLat/2)**2+Math.cos(rad(a.lat))*Math.cos(rad(b.lat))*Math.sin(dLon/2)**2;return 2*R*Math.asin(Math.sqrt(s))}
app.post("/api/routes/optimize",requireAuth,async(req,res,next)=>{try{if(req.user.role!=="admin"&&req.user.role!=="driver")return res.status(403).json({error:"Forbidden"});const date=req.body?.date||new Date().toISOString().slice(0,10),driverId=req.user.role==="driver"?req.user.id:req.body?.driverId;const params=[date];let sql="SELECT d.id,d.delivery_code code,d.customer_id,c.name customer,c.latitude,c.longitude FROM deliveries d JOIN customers c ON c.id=d.customer_id WHERE d.delivery_date=$1::date AND c.latitude IS NOT NULL AND c.longitude IS NOT NULL";if(driverId){params.push(driverId);sql+=" AND d.driver_id=$2"}const q=await pool.query(sql,params);if(!q.rows.length)return res.json({route:[],message:"No geocoded deliveries found."});const remaining=q.rows.map(r=>({...r,lat:Number(r.latitude),lon:Number(r.longitude)})),route=[];let current=remaining.shift();route.push(current);while(remaining.length){let best=0,bestDist=Infinity;remaining.forEach((x,i)=>{const dist=distance(current,x);if(dist<bestDist){bestDist=dist;best=i}});current=remaining.splice(best,1)[0];route.push(current)}await pool.query("UPDATE deliveries d SET route_order=x.ord,updated_at=NOW() FROM (SELECT id,row_number() over() ord FROM unnest($1::uuid[]) WITH ORDINALITY AS t(id,ord)) x WHERE d.id=x.id",[route.map(x=>x.id)]);res.json({route:route.map((x,i)=>({order:i+1,code:x.code,customer:x.customer,latitude:x.lat,longitude:x.lon}))})}catch(e){next(e)}});
app.get("/api/leaves",requireAuth,adminOnly,async(req,res,next)=>{try{const q=await pool.query("SELECT l.*,u.name driver FROM leaves l JOIN users u ON u.id=l.user_id ORDER BY l.leave_date DESC");res.json({leaves:q.rows})}catch(e){next(e)}});
app.post("/api/leaves",requireAuth,adminOnly,async(req,res,next)=>{try{const q=await pool.query("INSERT INTO leaves(user_id,leave_date,reason) VALUES($1,$2,$3) ON CONFLICT(user_id,leave_date) DO UPDATE SET reason=EXCLUDED.reason RETURNING *",[req.body.userId,req.body.leaveDate,req.body.reason||null]);res.status(201).json({leave:q.rows[0]})}catch(e){next(e)}});
app.delete("/api/leaves/:id",requireAuth,adminOnly,async(req,res,next)=>{try{await pool.query("DELETE FROM leaves WHERE id=$1",[req.params.id]);res.json({ok:true})}catch(e){next(e)}});
app.get("/api/health",async(_req,res)=>{const h={status:"ok",service:"tiffin-delivery-system",database:"not_configured"};if(pool){try{await pool.query("SELECT 1");h.database="connected"}catch{h.status="degraded";h.database="error"}}res.status(h.status==="ok"?200:503).json(h)});
app.use((req,res)=>{if(req.path.startsWith("/api/"))return res.status(404).json({error:"Not Found",message:"The requested resource was not found."});res.status(404).sendFile("404.html",{root:"public"});});
app.use((err,req,res,_next)=>{const status=Number.isInteger(err?.status)&&err.status>=400&&err.status<500?err.status:500;const requestId=crypto.randomUUID();if(status>=500)console.error("Request failed",{requestId,method:req.method,path:req.path,error:err?.message});if(res.headersSent)return;const message=status===413?"Request body is too large.":status===400?"Invalid request body.":"Something went wrong on the server.";res.status(status).json({error:status===500?"Internal Server Error":status===413?"Payload Too Large":"Bad Request",message,requestId})});
async function start(){try{await migrate();await seedDemoAccounts();app.listen(port,()=>console.log("Tiffin Delivery System running on port "+port))}catch(e){console.error("Startup failed:",e);process.exit(1)}}start();
