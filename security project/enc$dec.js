const te = new TextEncoder();
const td = new TextDecoder();

function show(msg,type){
  const d=document.getElementById("msg");
  d.className="msg "+type;
  d.textContent=msg;
  setTimeout(()=>d.textContent="",4000);
}

// ---------- Mono Key ----------
function generateMonoKey(){
  let a="ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");
  for(let i=a.length-1;i>0;i--){
    let j=Math.floor(Math.random()*(i+1));
    [a[i],a[j]]=[a[j],a[i]];
  }
  document.getElementById("monoKey").value=a.join("");
  show("Mono key generated","success");
}

function validateMono(key){
  key=(key||"").toUpperCase().replace(/[^A-Z]/g,"");
  if(key.length!==26 || new Set(key).size!==26){
    show("Invalid Mono Key (must be 26 unique A-Z letters)","error");
    return null;
  }
  return key;
}

// ---------- Base64 <-> Bytes ----------
function bytesToBase64(bytes){
  let bin="";
  const chunk=0x8000;
  for(let i=0;i<bytes.length;i+=chunk){
    bin+=String.fromCharCode(...bytes.subarray(i,i+chunk));
  }
  return btoa(bin);
}

function base64ToBytes(b64){
  const bin = atob((b64||"").trim());
  const out = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
  return out;
}

function otpKeyFromBase64(b64, requiredLen){
  try{
    const bytes = base64ToBytes(b64);
    if(bytes.length !== requiredLen) return null;
    return bytes;
  }catch(e){
    return null;
  }
}

// ---------- OTP (Base64) ----------
function generateOTP(){
  const txt=document.getElementById("text").value;
  if(!txt){ show("Enter text first","error"); return; }

  const plainBytes = te.encode(txt);
  const r = new Uint8Array(plainBytes.length);
  crypto.getRandomValues(r);

  // store as Base64 for safe copy/paste
  document.getElementById("otpKey").value = bytesToBase64(r);
  show("OTP generated as Base64 (save it!)","success");
}

// ---------- Crypto ----------
function mono(bytes,key,dec=false){
  let map={},rev={};
  for(let i=0;i<26;i++){
    map[65+i]=key.charCodeAt(i);
    rev[key.charCodeAt(i)]=65+i;
  }
  return bytes.map(b=>{
    if(b>=65&&b<=90) return dec?rev[b]:map[b];
    if(b>=97&&b<=122){
      let x=dec?rev[b-32]:map[b-32];
      return x+32;
    }
    return b;
  });
}

function otp(bytes,keyBytes){
  let out=new Uint8Array(bytes.length);
  for(let i=0;i<bytes.length;i++) out[i]=bytes[i]^keyBytes[i];
  return out;
}

async function hash(b){
  return new Uint8Array(await crypto.subtle.digest("SHA-256", b));
}

function pack(h,c){
  // header + hash + ciphertext (both base64)
  return "ENCv1|"+bytesToBase64(h)+"|"+bytesToBase64(c);
}

function unpack(t){
  let p=(t||"").trim().split("|");
  if(p[0]!=="ENCv1" || p.length!==3) throw "Corrupted file format";
  return {
    h: base64ToBytes(p[1]),
    c: base64ToBytes(p[2])
  };
}

// ---------- Encrypt ----------
async function encrypt(){
  let txt=document.getElementById("text").value;
  let monoKey=validateMono(document.getElementById("monoKey").value);
  if(!txt || !monoKey){
    show("Missing text or mono key","error"); return;
  }

  const plainBytes = te.encode(txt);

  const otpB64 = document.getElementById("otpKey").value;
  const otpBytes = otpKeyFromBase64(otpB64, plainBytes.length);
  if(!otpBytes){
    show(`Invalid OTP key. It must be Base64 and match text length (${plainBytes.length} bytes).`, "error");
    return;
  }

  let step1 = mono(plainBytes, monoKey, false);
  let cipher = otp(step1, otpBytes);
  let h = await hash(plainBytes);

  document.getElementById("output").textContent = pack(h, cipher);
  show("Encryption successful","success");
}

// ---------- Decrypt ----------
async function decrypt(){
  try{
    let txt=document.getElementById("text").value;
    let monoKey=validateMono(document.getElementById("monoKey").value);
    if(!txt || !monoKey) { show("Missing ciphertext or mono key","error"); return; }

    let {h,c} = unpack(txt);

    const otpB64 = document.getElementById("otpKey").value;
    const otpBytes = otpKeyFromBase64(otpB64, c.length);
    if(!otpBytes) throw `Wrong OTP key (must match ${c.length} bytes)`;

    let step1 = otp(c, otpBytes);
    let plain = mono(step1, monoKey, true);

    let chk = await hash(plain);
    if(bytesToBase64(chk) !== bytesToBase64(h))
      throw "Wrong key or corrupted data (checksum mismatch)";

    document.getElementById("output").textContent = td.decode(plain);
    show("Decryption successful","success");
  }catch(e){
    show(String(e), "error");
  }
}


function loadFile(){
  let f=document.getElementById("fileInput").files[0];
  if(!f){ show("Choose file","error"); return; }
  let r=new FileReader();
  r.onload=()=>{ document.getElementById("text").value=r.result; };
  r.readAsText(f);
}

function download(name){
  let c=document.getElementById("output").textContent;
  if(!c){ show("Nothing to download","error"); return; }
  let a=document.createElement("a");
  a.href=URL.createObjectURL(new Blob([c], {type:"text/plain;charset=utf-8"}));
  a.download=name;
  a.click();
}

const themeBtn = document.getElementById("themeToggle");

function setTheme(isDark){
  document.body.classList.toggle("dark", isDark);
  themeBtn.textContent = isDark ? "☀️ Light mode" : "🌙 Dark mode";
  localStorage.setItem("theme", isDark ? "dark" : "light");
}


const saved = localStorage.getItem("theme");
setTheme(saved === "dark");


themeBtn.addEventListener("click", () => {
  const isDark = !document.body.classList.contains("dark");
  setTheme(isDark);
});
