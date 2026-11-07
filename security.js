/* Hem Saldo v12 – local app lock. No Firebase or budget data is modified here. */
(function(){
'use strict';
const KEY='hs_app_lock_v1';
const enc=new TextEncoder();
const gate=document.getElementById('security-gate');
const pinInput=document.getElementById('sec-pin');
const pinBtn=document.getElementById('sec-pin-btn');
const faceBtn=document.getElementById('sec-face-btn');
const errorEl=document.getElementById('sec-error');
let busy=false, unlocked=false, attempts=0, cooldown=0, needsLock=false;
let config=read();
function read(){try{return JSON.parse(localStorage.getItem(KEY)||'null')}catch{return null}}
function save(){localStorage.setItem(KEY,JSON.stringify(config))}
function b64(bytes){return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function from64(s){let x=atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4));return Uint8Array.from(x,c=>c.charCodeAt(0))}
function random(n){let b=new Uint8Array(n);crypto.getRandomValues(b);return b}
function secure(){return !!(window.isSecureContext&&crypto?.subtle)}
async function digestPin(pin,salt){let key=await crypto.subtle.importKey('raw',enc.encode(pin),'PBKDF2',false,['deriveBits']);return b64(await crypto.subtle.deriveBits({name:'PBKDF2',salt:from64(salt),iterations:180000,hash:'SHA-256'},key,256))}
function validPin(pin){return /^\d{4,8}$/.test(pin)}
function message(t){errorEl.textContent=t||''}
function showLock(){if(!config?.pinHash)return;unlocked=false;gate.hidden=false;document.body.classList.add('sec-locked');pinInput.value='';faceBtn.hidden=!config.passkey;message('');pinInput.focus({preventScroll:true})}
function openLock(){unlocked=true;needsLock=false;gate.hidden=true;document.body.classList.remove('sec-locked');pinInput.value='';message('');attempts=0}
function lockNow(){if(config?.pinHash)showLock()}
async function unlockPin(){if(busy)return;if(Date.now()<cooldown){message('Vänta en stund innan du försöker igen.');return}let pin=pinInput.value;if(!validPin(pin)){message('Ange din PIN-kod (4–8 siffror).');return}busy=true;pinBtn.disabled=true;try{let hash=await digestPin(pin,config.pinSalt);if(hash===config.pinHash){openLock()}else{attempts++;pinInput.value='';message('Fel PIN-kod.');if(attempts>=5){cooldown=Date.now()+30000;attempts=0;message('För många försök. Vänta 30 sekunder.')}}}catch{message('Kunde inte kontrollera PIN-koden.')}finally{busy=false;pinBtn.disabled=false}}
pinBtn.addEventListener('click',unlockPin);
pinInput.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();unlockPin()}});
// Verify WebAuthn authentication locally using stored public key. This is a convenience lock,
// not a replacement for Firebase authentication or server-side authorization.
function derToRaw(sig){let b=new Uint8Array(sig),i=0;function len(){let n=b[i++];if(n&128){let x=n&127;n=0;while(x--)n=(n<<8)|b[i++]}return n}if(b[i++]!==0x30)throw Error('Bad ECDSA');len();function integer(){if(b[i++]!==2)throw Error('Bad ECDSA integer');let n=len(),x=b.slice(i,i+n);i+=n;while(x.length>32&&x[0]===0)x=x.slice(1);if(x.length>32)throw Error('Bad ECDSA size');let y=new Uint8Array(32);y.set(x,32-x.length);return y}let r=integer(),s=integer(),out=new Uint8Array(64);out.set(r);out.set(s,32);return out}
function concat(a,b){let out=new Uint8Array(a.byteLength+b.byteLength);out.set(new Uint8Array(a),0);out.set(new Uint8Array(b),a.byteLength);return out}
async function faceUnlock(){if(busy||!config?.passkey)return;busy=true;faceBtn.disabled=true;message('Bekräfta med Face ID eller enhetslås…');try{const challenge=random(32);const credential=await navigator.credentials.get({publicKey:{challenge,allowCredentials:[{type:'public-key',id:from64(config.passkey.id)}],userVerification:'required',timeout:60000}});if(!credential||b64(credential.rawId)!==config.passkey.id)throw Error('Fel nyckel');let data=JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));if(data.type!=='webauthn.get'||data.challenge!==b64(challenge)||data.origin!==location.origin)throw Error('Ogiltig verifiering');let auth=new Uint8Array(credential.response.authenticatorData);if(!(auth[32]&4))throw Error('Enheten verifierade inte användaren');let digest=await crypto.subtle.digest('SHA-256',credential.response.clientDataJSON);let payload=concat(auth,digest);let algo=config.passkey.alg;let key=await crypto.subtle.importKey('spki',from64(config.passkey.publicKey),algo===-7?{name:'ECDSA',namedCurve:'P-256'}:{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);let ok=await crypto.subtle.verify(algo===-7?{name:'ECDSA',hash:'SHA-256'}:{name:'RSASSA-PKCS1-v1_5'},key,algo===-7?derToRaw(credential.response.signature):credential.response.signature,payload);if(!ok)throw Error('Ogiltig signatur');openLock()}catch(e){message('Kunde inte låsa upp med enheten. Använd PIN-koden.')}finally{busy=false;faceBtn.disabled=false}}
faceBtn.addEventListener('click',faceUnlock);
async function setPin(){if(!secure()){alert('PIN-kod kräver HTTPS eller en säker lokal miljö.');return}let first=prompt('Välj en PIN-kod med 4–8 siffror');if(first===null)return;if(!validPin(first)){alert('PIN-koden måste bestå av 4–8 siffror.');return}let second=prompt('Upprepa din nya PIN-kod');if(second!==first){alert('PIN-koderna matchar inte.');return}if(config?.pinHash){let old=prompt('Ange din nuvarande PIN-kod för att ändra');if(old===null)return;let hash=await digestPin(old,config.pinSalt);if(hash!==config.pinHash){alert('Fel nuvarande PIN-kod.');return}}
const salt=b64(random(16));config={...config,pinSalt:salt,pinHash:await digestPin(first,salt)};save();openLock();renderSettings();alert('PIN-lås aktiverat. Appen låses nästa gång du öppnar den eller återvänder till den.')}
async function removePin(){if(!config?.pinHash)return;let old=prompt('Ange PIN-koden för att stänga av applåset');if(old===null)return;if(await digestPin(old,config.pinSalt)!==config.pinHash){alert('Fel PIN-kod.');return}if(!confirm('Stänga av PIN och Face ID-låset?'))return;config=null;localStorage.removeItem(KEY);openLock();renderSettings()}
let facePinVerified=false,faceStep=0,faceMsg='',faceSupport=null,registering=false;
function esc(t){return String(t==null?'':t).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
if(window.PublicKeyCredential&&PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable){PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(v=>{faceSupport=!!v;renderSettings()}).catch(()=>{})}
function setFaceMsg(t){faceMsg=t||'';let el=document.getElementById('face-msg');if(el)el.textContent=faceMsg}
function startFace(){if(!config?.pinHash){setFaceMsg('Aktivera PIN-kod först.');return}faceStep=1;facePinVerified=false;faceMsg='';renderSettings();setTimeout(()=>{let i=document.getElementById('face-pin');if(i)i.focus()},60)}
function cancelFace(){faceStep=0;facePinVerified=false;faceMsg='';renderSettings()}
async function registerFace(){
  if(!config?.pinHash){setFaceMsg('Aktivera PIN-kod först.');return}
  if(!secure()||!window.PublicKeyCredential||!navigator.credentials||!navigator.credentials.create){setFaceMsg('Den här webbläsaren eller appen stödjer inte Face ID-nycklar (passkeys) i detta läge. PIN fungerar ändå.');return}
  const pin=(document.getElementById('face-pin')?.value||'').trim();
  if(!validPin(pin)){setFaceMsg('Skriv din PIN-kod (4–8 siffror).');return}
  setFaceMsg('Kontrollerar PIN…');
  try{if(await digestPin(pin,config.pinSalt)!==config.pinHash){setFaceMsg('Fel PIN-kod.');return}}catch(e){setFaceMsg('Kunde inte kontrollera PIN-koden.');return}
  facePinVerified=true;faceStep=2;faceMsg='PIN godkänd. Tryck nu på knappen "Slutför Face ID".';renderSettings();
}
function faceHint(code){
  if(code==='NotAllowedError')return 'Avbröts eller blockerades av enheten. Kontrollera att Face ID är på för Safari/appar och att lösenord/iCloud-nyckelring är aktiverat, och försök igen.';
  if(code==='SecurityError')return 'Adressen tillåter inte nycklar (kräver HTTPS på er riktiga adress).';
  if(code==='NotSupportedError')return 'Enheten eller appen stödjer inte detta.';
  if(code==='InvalidStateError')return 'Det finns redan en nyckel för appen på enheten.';
  if(code==='public-key-unavailable')return 'Enheten gav ingen publik nyckel (för gammal iOS/webbläsare).';
  return '';
}
async function finishFace(){
  if(!facePinVerified||!config?.pinHash)return;
  // Direct tap: no awaited work before navigator.credentials.create (iOS needs a fresh gesture).
  facePinVerified=false;registering=true;
  const btn=document.getElementById('sec-face-finish');if(btn)btn.disabled=true;
  setFaceMsg('Väntar på Face ID…');
  try{
    const options={publicKey:{challenge:random(32),rp:{name:'Hem Saldo'},user:{id:random(16),name:'hemsaldo-'+b64(random(8)),displayName:'Hem Saldo'},pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'preferred',userVerification:'required'},attestation:'none',timeout:60000}};
    const credential=await navigator.credentials.create(options);
    if(!credential?.response?.getPublicKey)throw Error('public-key-unavailable');
    const publicKey=credential.response.getPublicKey(),alg=credential.response.getPublicKeyAlgorithm();
    if(!publicKey||![-7,-257].includes(alg))throw Error('public-key-unavailable');
    config.passkey={id:b64(credential.rawId),publicKey:b64(publicKey),alg};
    save();faceStep=0;faceMsg='';renderSettings();
    alert('Face ID / enhetslås är aktiverat. Din PIN-kod fungerar fortfarande som reserv.');
  }catch(e){
    const code=e?.name&&e.name!=='Error'?e.name:(e?.message||'Okänt fel');
    faceStep=0;faceMsg='Kunde inte aktivera Face ID. Felkod: '+code+'. '+faceHint(code);
    renderSettings();
  }finally{registering=false}
}
async function removeFace(){if(!config?.passkey)return;let pin=prompt('Ange PIN-koden för att ta bort enhetslåset');if(pin===null)return;if(await digestPin(pin,config.pinSalt)!==config.pinHash){alert('Fel PIN-kod.');return}delete config.passkey;save();renderSettings()}
function facePart(){
  if(!config?.pinHash)return '';
  if(config.passkey)return '<p class="green">✓ Face ID / enhetslås är aktiverat</p><button class="btn secondary small" onclick="HemSecurity.removeFace()">Ta bort Face ID</button>';
  let h='<p class="smallnote" style="margin-top:14px">Vill du även låsa upp med Face ID?</p>';
  if(faceSupport===false)h+='<p class="warn smallnote">Enheten rapporterar att Face ID / skärmlås inte kan användas av webbappar här. PIN fungerar ändå.</p>';
  if(faceStep===0)h+='<button class="btn secondary" onclick="HemSecurity.startFace()">Aktivera Face ID / enhetslås</button>';
  if(faceStep===1)h+='<label>Din PIN-kod<input id="face-pin" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="8" autocomplete="off" placeholder="PIN-kod"></label><button class="btn secondary" onclick="HemSecurity.registerFace()">Fortsätt</button> <button class="btn ghost small" onclick="HemSecurity.cancelFace()">Avbryt</button>';
  if(faceStep===2)h+='<button id="sec-face-finish" class="btn" onclick="HemSecurity.finishFace()">Slutför Face ID – tryck här</button> <button class="btn ghost small" onclick="HemSecurity.cancelFace()">Avbryt</button>';
  return h+'<p id="face-msg" class="smallnote" style="margin-top:8px">'+esc(faceMsg)+'</p>';
}
function renderSettings(){let el=document.getElementById('security-settings');if(!el)return;el.innerHTML='<h3>App-lås – PIN och Face ID</h3><p class="smallnote">Lås appen när den öppnas och när du återvänder till den. PIN fungerar som reserv. Face ID kan på vissa enheter ersättas med enhetens lösenkod.</p>'+(config?.pinHash?'<p class="green">✓ PIN-kod är aktiverad</p><button class="btn secondary small" onclick="HemSecurity.setPin()">Ändra PIN</button> <button class="btn secondary small" onclick="HemSecurity.lockNow()">Lås nu</button> <button class="btn ghost small" onclick="HemSecurity.removePin()">Stäng av lås</button>':'<button class="btn" onclick="HemSecurity.setPin()">Aktivera PIN-kod</button>')+facePart()+'<p class="smallnote" style="margin-top:14px">Detta är ett lokalt skärmlås, inte kryptering av budgetdata. Firebase-inloggning och Firestore-regler skyddar molnkontot separat. Om webbläsardata raderas försvinner PIN-inställningen.</p>'}
window.HemSecurity={setPin,removePin,startFace,cancelFace,registerFace,finishFace,removeFace,lockNow,renderSettings};
if(config?.pinHash)showLock();else openLock();
document.addEventListener('visibilitychange',()=>{if(document.hidden){needsLock=true}else if(needsLock&&!busy&&!registering&&unlocked){lockNow();needsLock=false}});
window.addEventListener('pagehide',()=>{needsLock=true});
window.addEventListener('pageshow',()=>{if(needsLock&&!busy&&!registering&&unlocked){lockNow();needsLock=false}});
// Browser zoom controls (the user's explicit preference); preserve normal scrolling.
document.addEventListener('gesturestart',e=>e.preventDefault(),{passive:false});
document.addEventListener('gesturechange',e=>e.preventDefault(),{passive:false});
})();
