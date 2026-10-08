import "dotenv/config";
import express from "express";
import pg from "pg";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";

const { Pool } = pg;
const app = express();
const port = Number(process.env.PORT || 3000);
app.disable("x-powered-by"); app.set("trust proxy", 1);
app.use((_req,res,next)=>{res.setHeader("X-Content-Type-Options","nosniff");res.setHeader("X-Frame-Options","DENY");res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");res.setHeader("Permissions-Policy","camera=(self), geolocation=(self), microphone=()");next()});
const ALLOWED_ORIGINS=new Set(["https://instant-wjihasssodpr-angadphuket345-140e.wix-site-host.com","http://localhost:3000","http://localhost:5173"]);
app.use((req,res,next)=>{const origin=req.headers.origin;if(origin&&ALLOWED_ORIGINS.has(origin)){res.setHeader("Access-Control-Allow-Origin",origin);res.setHeader("Vary","Origin");res.setHeader("Access-Control-Allow-Headers","Content-Type, Authorization");res.setHeader("Access-Control-Allow-Methods","GET,POST,PATCH,DELETE,OPTIONS")}if(req.method==="OPTIONS")return res.sendStatus(204);next()});
app.use(express.json({limit:"12mb"}));app.use((_req,res,next)=>{res.setHeader("Cache-Control","no-store");next()});app.use(express.static("public"));
const pool=process.env.DATABASE_URL?new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false}}):null;
const SESSION_SECRET=process.env.SESSION_SECRET||"change-this-in-production";
function createSessionToken(user){const payload=Buffer.from(JSON.stringify({...user,exp:Date.now()+12*60*60*1000})).toString("base64url");const sig=crypto.createHmac("sha256",SESSION_SECRET).update(payload).digest("base64url");return payload+"."+sig}
function readSessionToken(token){if(!token)return null;const p=token.split(".");if(p.length!==2)return null;const [payload,sig]=p,expected=crypto.createHmac("sha256",SESSION_SECRET).update(payload).digest("base64url");if(sig.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected)))return null;try{const s=JSON.parse(Buffer.from(payload,"base64url").toString());return s.exp>Date.now()?s:null}catch{return null}}
function requireAuth(req,res,next){const s=readSessionToken(req.headers.authorization?.replace(/^Bearer\\s+/i,""));if(!s)return res.status(401).json({error:"Unauthorized",message:"Please sign in again."});req.user=s;next()}
function adminOnly(req,res,next){if(req.user?.role!=="admin")return res.status(403).json({error:"Forbidden",message:"Admin access required."});next()}
async function migrate(){if(!pool)return;await pool.query(`-- Production V1 database schema
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
  await pool.query(\`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT, ADD COLUMN IF NOT EXISTS on_duty BOOLEAN NOT NULL DEFAULT FALSE\`);
  await pool.query(\`ALTER TABLE customers ADD COLUMN IF NOT EXISTS whatsapp_number TEXT, ADD COLUMN IF NOT EXISTS address TEXT, ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION, ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION, ADD COLUMN IF NOT EXISTS delivery_window_start TIME, ADD COLUMN IF NOT EXISTS delivery_window_end TIME, ADD COLUMN IF NOT EXISTS instructions TEXT\`);
  await pool.query(\`ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS recurring_delivery_id UUID, ADD COLUMN IF NOT EXISTS route_order INTEGER, ADD COLUMN IF NOT EXISTS meal_type TEXT NOT NULL DEFAULT 'Lunch', ADD COLUMN IF NOT EXISTS whatsapp_message_id TEXT\`);
  // V1 migration: allow more than one meal/delivery per customer on the same date.
  // Older demo databases may still have the original two-column unique constraint.
  await pool.query(`ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS meal_type TEXT NOT NULL DEFAULT 'Lunch'`);
  await pool.query(`ALTER TABLE deliveries DROP CONSTRAINT IF EXISTS deliveries_customer_id_delivery_date_key`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS deliveries_customer_date_meal_key ON deliveries(customer_id, delivery_date, meal_type)`);
  const hash=await bcrypt.hash("demo123",10);if(process.env.DEMO_SEED==="true"){await pool.query("INSERT INTO users(username,password_hash,role,name) VALUES('admin',$1,'admin','Admin') ON CONFLICT(username) DO NOTHING",[hash]);await pool.query("INSERT INTO users(username,password_hash,role,name) VALUES('driver',$1,'driver','Rahul') ON CONFLICT(username) DO NOTHING",[hash]);}}
function dayNumber(d){return ((d.getUTCDay()+6)%7)+1}
async function generateDailyDeliveries(date=new Date().toISOString().slice(0,10)){if(!pool)return{created:0};const result=await pool.query(`INSERT INTO deliveries(delivery_code,customer_id,driver_id,recurring_delivery_id,delivery_date,planned_time,meal_type,status)
SELECT 'DEL-'||upper(substr(md5(r.id::text||':'||$1),1,8)),r.customer_id,r.driver_id,r.id,$1,r.delivery_time,r.meal_type,'Pending'
FROM recurring_deliveries r JOIN customers c ON c.id=r.customer_id
WHERE r.active AND c.active AND ($1::date >= COALESCE(r.paused_until,'1900-01-01')) AND extract(isodow from $1::date)::int=ANY(r.days_of_week)
AND NOT EXISTS(SELECT 1 FROM deliveries d WHERE d.customer_id=r.customer_id AND d.delivery_date=$1 AND d.meal_type=r.meal_type)
ON CONFLICT(customer_id,delivery_date,meal_type) DO NOTHING RETURNING id`,[date]);return{created:result.rowCount}}
app.post("/api/login",async(req,res,next)=>{try{if(!pool)return res.status(503).json({error:"Database unavailable"});const username=String(req.body?.username||"").trim().toLowerCase(),password=String(req.body?.password||"");const q=await pool.query("SELECT id,username,password_hash,role,name FROM users WHERE username=$1 AND active=true LIMIT 1",[username]);const u=q.rows[0];if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"Invalid credentials",message:"Staff ID or password is incorrect."});const safe={id:u.id,username:u.username,role:u.role,name:u.name};res.json({token:createSessionToken(safe),user:safe})}catch(e){next(e)}});
app.post("/api/profile/password",requireAuth,async(req,res,next)=>{try{const current=String(req.body?.currentPassword||""),nextPw=String(req.body?.newPassword||"");if(nextPw.length<8)return res.status(400).json({error:"Invalid password",message:"New password must be at least 8 characters."});const q=await pool.query("SELECT password_hash FROM users WHERE id=$1 AND active=true",[req.user.id]);if(!q.rows[0]||!(await bcrypt.compare(current,q.rows[0].password_hash)))return res.status(401).json({error:"Invalid credentials",message:"Current password is incorrect."});await pool.query("UPDATE users SET password_hash=$1,updated_at=NOW() WHERE id=$2",[await bcrypt.hash(nextPw,12),req.user.id]);res.json({ok:true})}catch(e){next(e)}});
app.post("/api/logout",requireAuth,(_req,res)=>res.json({ok:true}));
app.get("/api/customers",requireAuth,async(req,res,next)=>{try{const q=await pool.query("SELECT * FROM customers ORDER BY name");res.json({customers:q.rows})}catch(e){next(e)}});
app.post("/api/customers",requireAuth,adminOnly,async(req,res,next)=>{try{const b=req.body||{};if(!b.name||!b.address)return res.status(400).json({error:"Name and address are required"});const code=b.customerCode||"C-"+crypto.randomUUID().slice(0,8).toUpperCase();const q=await pool.query(`INSERT INTO customers(customer_code,name,phone,whatsapp_number,address,area,latitude,longitude,delivery_window_start,delivery_window_end,instructions) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,[code,b.name,b.phone||null,b.whatsappNumber||b.phone||null,b.address,b.area||null,b.latitude??null,b.longitude??null,b.deliveryWindowStart||null,b.deliveryWindowEnd||null,b.instructions||null]);res.status(201).json({customer:q.rows[0]})}catch(e){next(e)}});
app.patch("/api/customers/:id",requireAuth,adminOnly,async(req,res,next)=>{try{const b=req.body||{};const q=await pool.query(`UPDATE customers SET name=COALESCE($1,name),phone=COALESCE($2,phone),whatsapp_number=COALESCE($3,whatsapp_number),address=COALESCE($4,address),area=COALESCE($5,area),latitude=COALESCE($6,latitude),longitude=COALESCE($7,longitude),active=COALESCE($8,active),updated_at=NOW() WHERE id=$9 RETURNING *`,[b.name,b.phone,b.whatsappNumber,b.address,b.area,b.latitude,b.longitude,b.active,b.id||req.params.id]);if(!q.rows[0])return res.status(404).json({error:"Customer not found"});res.json({customer:q.rows[0]})}catch(e){next(e)}});
app.delete("/api/customers/:id",requireAuth,adminOnly,async(req,res,next)=>{try{await pool.query("UPDATE customers SET active=false,updated_at=NOW() WHERE id=$1",[req.params.id]);res.json({ok:true})}catch(e){next(e)}});
app.get("/api/staff",requireAuth,adminOnly,async(req,res,next)=>{try{const q=await pool.query("SELECT id,username,name,phone,role,active,on_duty FROM users WHERE role='driver' ORDER BY name");res.json({staff:q.rows})}catch(e){next(e)}});
app.post("/api/staff",requireAuth,adminOnly,async(req,res,next)=>{try{const b=req.body||{};if(!b.username||!b.name||!b.password)return res.status(400).json({error:"Username, name and password are required"});const q=await pool.query("INSERT INTO users(username,password_hash,role,name,phone) VALUES($1,$2,'driver',$3,$4) RETURNING id,username,name,phone,role,active,on_duty",[b.username.toLowerCase(),await bcrypt.hash(b.password,12),b.name,b.phone||null]);res.status(201).json({staff:q.rows[0]})}catch(e){next(e)}});
app.patch("/api/staff/:id",requireAuth,adminOnly,async(req,res,next)=>{try{const b=req.body||{};const q=await pool.query("UPDATE users SET name=COALESCE($1,name),phone=COALESCE($2,phone),active=COALESCE($3,active),on_duty=COALESCE($4,on_duty),updated_at=NOW() WHERE id=$5 AND role='driver' RETURNING id,username,name,phone,role,active,on_duty",[b.name,b.phone,b.active,b.onDuty,req.params.id]);if(!q.rows[0])return res.status(404).json({error:"Driver not found"});res.json({staff:q.rows[0]})}catch(e){next(e)}});
app.patch("/api/staff/:id/duty",requireAuth,async(req,res,next)=>{try{const id=req.user.role==="driver"?req.user.id:req.params.id;const onDuty=Boolean(req.body?.onDuty);const q=await pool.query("UPDATE users SET on_duty=$1,updated_at=NOW() WHERE id=$2 AND role='driver' RETURNING id,on_duty",[onDuty,id]);if(!q.rows[0])return res.status(404).json({error:"Driver not found"});res.json({staff:q.rows[0]})}catch(e){next(e)}});
app.get("/api/recurring-deliveries",requireAuth,adminOnly,async(req,res,next)=>{try{const q=await pool.query(`SELECT r.*,c.name customer,c.address,c.area,u.name driver FROM recurring_deliveries r JOIN customers c ON c.id=r.customer_id LEFT JOIN users u ON u.id=r.driver_id ORDER BY r.active DESC,r.delivery_time`);res.json({deliveries:q.rows})}catch(e){next(e)}});
app.post("/api/recurring-deliveries",requireAuth,adminOnly,async(req,res,next)=>{try{const b=req.body||{};if(!b.customerId)return res.status(400).json({error:"Customer is required"});const q=await pool.query(`INSERT INTO recurring_deliveries(customer_id,driver_id,meal_type,delivery_time,days_of_week,paused_until,notes) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[b.customerId,b.driverId||null,b.mealType||"Lunch",b.deliveryTime||null,b.daysOfWeek||[1,2,3,4,5,6],b.pausedUntil||null,b.notes||null]);res.status(201).json({delivery:q.rows[0]})}catch(e){next(e)}});
app.patch("/api/recurring-deliveries/:id",requireAuth,adminOnly,async(req,res,next)=>{try{const b=req.body||{};const q=await pool.query("UPDATE recurring_deliveries SET driver_id=COALESCE($1,driver_id),delivery_time=COALESCE($2,delivery_time),days_of_week=COALESCE($3,days_of_week),active=COALESCE($4,active),paused_until=$5,notes=COALESCE($6,notes),updated_at=NOW() WHERE id=$7 RETURNING *",[b.driverId,b.deliveryTime,b.daysOfWeek,b.active,b.pausedUntil??null,b.notes,req.params.id]);if(!q.rows[0])return res.status(404).json({error:"Recurring delivery not found"});res.json({delivery:q.rows[0]})}catch(e){next(e)}});
app.delete("/api/recurring-deliveries/:id",requireAuth,adminOnly,async(req,res,next)=>{try{await pool.query("UPDATE recurring_deliveries SET active=false,updated_at=NOW() WHERE id=$1",[req.params.id]);res.json({ok:true})}catch(e){next(e)}});
app.post("/api/deliveries/generate",requireAuth,adminOnly,async(req,res,next)=>{try{res.json(await generateDailyDeliveries(req.body?.date||new Date().toISOString().slice(0,10)))}catch(e){next(e)}});
app.post("/api/deliveries",requireAuth,adminOnly,async(req,res,next)=>{try{
  const b=req.body||{};
  if(!b.customerId||!b.deliveryDate)return res.status(400).json({error:"Customer and delivery date are required"});
  const mealType=String(b.mealType||"Lunch").trim()||"Lunch";
  const code="DEL-"+crypto.randomUUID().replace(/-/g,"").slice(0,8).toUpperCase();
  const q=await pool.query(`INSERT INTO deliveries(delivery_code,customer_id,driver_id,delivery_date,planned_time,meal_type,status)
    VALUES($1,$2,$3,$4,$5,$6,'Pending') RETURNING *`,
    [code,b.customerId,b.driverId||null,b.deliveryDate,b.plannedTime||null,mealType]);
  res.status(201).json({delivery:q.rows[0]});
}catch(e){next(e)}});
app.delete("/api/deliveries/:id",requireAuth,adminOnly,async(req,res,next)=>{try{
  const q=await pool.query("UPDATE deliveries SET status='Cancelled',updated_at=NOW() WHERE id=$1 AND status NOT IN ('Delivered','Cancelled') RETURNING id,delivery_code code,status",[req.params.id]);
  if(!q.rows[0])return res.status(404).json({error:"Delivery not found or already completed."});
  res.json({delivery:q.rows[0]});
}catch(e){next(e)}});
app.get("/api/deliveries",requireAuth,async(req,res,next)=>{try{const date=req.query.date||new Date().toISOString().slice(0,10);await generateDailyDeliveries(date);const params=[date];let where="d.delivery_date=$1";if(req.user.role==="driver"){params.push(req.user.id);where+=" AND d.driver_id=$2"}const q=await pool.query(`SELECT d.id,d.delivery_code code,d.delivery_date,d.meal_type,c.id customer_id,c.name customer,c.phone,c.whatsapp_number,c.address,c.area,c.latitude,c.longitude,u.id driver_id,u.name driver,d.status,d.route_order,COALESCE(TO_CHAR(d.planned_time,'HH12:MI AM'),'') time,d.empty_photo_data IS NOT NULL has_empty_photo,d.delivery_photo_data IS NOT NULL has_delivery_photo,d.whatsapp_status FROM deliveries d JOIN customers c ON c.id=d.customer_id LEFT JOIN users u ON u.id=d.driver_id WHERE ${where} ORDER BY d.route_order NULLS LAST,d.planned_time NULLS LAST,c.name`,params);res.json({deliveries:q.rows})}catch(e){next(e)}});
app.post("/api/deliveries/:code/empty-proof",requireAuth,async(req,res,next)=>{try{if(req.user.role!=="driver")return res.status(403).json({error:"Forbidden"});const b=req.body||{};if(!b.photo)return res.status(400).json({error:"Photo required"});const q=await pool.query("UPDATE deliveries SET status='Empty Tiffin Collected',empty_photo_data=$1,empty_photo_at=NOW(),empty_latitude=$2,empty_longitude=$3,updated_at=NOW() WHERE delivery_code=$4 AND driver_id=$5 AND status IN ('Pending','Planned','Empty Tiffin Collected') RETURNING delivery_code code,status",[b.photo,b.latitude??null,b.longitude??null,req.params.code,req.user.id]);if(!q.rows[0])return res.status(404).json({error:"Delivery not found"});res.json({delivery:q.rows[0]})}catch(e){next(e)}});
app.post("/api/deliveries/:code/complete",requireAuth,async(req,res,next)=>{try{if(req.user.role!=="driver")return res.status(403).json({error:"Forbidden"});const b=req.body||{};if(!b.photo)return res.status(400).json({error:"Photo required"});const q=await pool.query("UPDATE deliveries SET status='Delivered',delivery_photo_data=$1,delivery_photo_at=NOW(),delivered_at=NOW(),delivery_latitude=$2,delivery_longitude=$3,whatsapp_status='Queued',updated_at=NOW() WHERE delivery_code=$4 AND driver_id=$5 AND empty_photo_data IS NOT NULL AND status IN ('Empty Tiffin Collected','Pending') RETURNING delivery_code code,status,delivered_at,customer_id",[b.photo,b.latitude??null,b.longitude??null,req.params.code,req.user.id]);if(!q.rows[0])return res.status(409).json({error:"Collect the empty-tiffin photo before completing delivery."});/* WhatsApp provider call will be attached once the client supplies provider credentials. */res.json({delivery:q.rows[0],whatsapp:"Queued"})}catch(e){next(e)}});
app.get("/api/deliveries/:code/proof",requireAuth,async(req,res,next)=>{try{const q=await pool.query("SELECT d.delivery_code code,c.name customer,u.name driver,d.status,d.empty_photo_data,d.empty_photo_at,d.empty_latitude,d.empty_longitude,d.delivery_photo_data,d.delivery_photo_at,d.delivery_latitude,d.delivery_longitude,d.delivered_at,d.whatsapp_status FROM deliveries d JOIN customers c ON c.id=d.customer_id LEFT JOIN users u ON u.id=d.driver_id WHERE d.delivery_code=$1 AND ($2='admin' OR d.driver_id=$3)",[req.params.code,req.user.role,req.user.id]);if(!q.rows[0])return res.status(404).json({error:"Proof not found"});res.json({proof:q.rows[0]})}catch(e){next(e)}});
function distance(a,b){const R=6371,rad=x=>x*Math.PI/180,dLat=rad(b.lat-a.lat),dLon=rad(b.lon-a.lon),s=Math.sin(dLat/2)**2+Math.cos(rad(a.lat))*Math.cos(rad(b.lat))*Math.sin(dLon/2)**2;return 2*R*Math.asin(Math.sqrt(s))}
app.post("/api/routes/optimize",requireAuth,adminOnly,async(req,res,next)=>{try{const date=req.body?.date||new Date().toISOString().slice(0,10),driverId=req.body?.driverId;const params=[date];let sql="SELECT d.id,d.delivery_code code,d.customer_id,c.name customer,c.latitude,c.longitude FROM deliveries d JOIN customers c ON c.id=d.customer_id WHERE d.delivery_date=$1 AND c.latitude IS NOT NULL AND c.longitude IS NOT NULL";if(driverId){params.push(driverId);sql+=" AND d.driver_id=$2"}const q=await pool.query(sql,params);if(!q.rows.length)return res.json({route:[],message:"No geocoded deliveries found."});const remaining=q.rows.map(r=>({...r,lat:Number(r.latitude),lon:Number(r.longitude)})),route=[];let current=remaining.shift();route.push(current);while(remaining.length){let best=0,bestDist=Infinity;remaining.forEach((x,i)=>{const dist=distance(current,x);if(dist<bestDist){bestDist=dist;best=i}});current=remaining.splice(best,1)[0];route.push(current)}await pool.query("UPDATE deliveries d SET route_order=x.ord,updated_at=NOW() FROM (SELECT id,row_number() over() ord FROM unnest($1::bigint[]) WITH ORDINALITY AS t(id,ord)) x WHERE d.id=x.id",[route.map(x=>x.id)]);res.json({route:route.map((x,i)=>({order:i+1,code:x.code,customer:x.customer,latitude:x.lat,longitude:x.lon}))})}catch(e){next(e)}});
app.get("/api/leaves",requireAuth,adminOnly,async(req,res,next)=>{try{const q=await pool.query("SELECT l.*,u.name driver FROM leaves l JOIN users u ON u.id=l.user_id ORDER BY l.leave_date DESC");res.json({leaves:q.rows})}catch(e){next(e)}});
app.post("/api/leaves",requireAuth,adminOnly,async(req,res,next)=>{try{const q=await pool.query("INSERT INTO leaves(user_id,leave_date,reason) VALUES($1,$2,$3) ON CONFLICT(user_id,leave_date) DO UPDATE SET reason=EXCLUDED.reason RETURNING *",[req.body.userId,req.body.leaveDate,req.body.reason||null]);res.status(201).json({leave:q.rows[0]})}catch(e){next(e)}});
app.delete("/api/leaves/:id",requireAuth,adminOnly,async(req,res,next)=>{try{await pool.query("DELETE FROM leaves WHERE id=$1",[req.params.id]);res.json({ok:true})}catch(e){next(e)}});
app.get("/api/health",async(_req,res)=>{const h={status:"ok",service:"tiffin-delivery-system",database:"not_configured"};if(pool){try{await pool.query("SELECT 1");h.database="connected"}catch{h.status="degraded";h.database="error"}}res.status(h.status==="ok"?200:503).json(h)});
app.use((_req,res)=>res.status(404).json({error:"Not Found",message:"The requested resource was not found."}));app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:"Internal Server Error",message:"Something went wrong on the server."})});
async function start(){try{await migrate();app.listen(port,()=>console.log("Tiffin Delivery System running on port "+port))}catch(e){console.error("Startup failed:",e);process.exit(1)}}start();
