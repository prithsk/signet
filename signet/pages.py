"""Signer-facing pages. Plain HTML strings with __PLACEHOLDER__ substitution. No build step."""

_STYLE = """<style>
:root{--ink:#17181c;--paper:#f6f4ee;--line:#c9c4b6;--seal:#8b1e2d;--muted:#6b6862}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:17px/1.5 Georgia,'Times New Roman',serif}
main{max-width:600px;margin:6vh auto;padding:0 20px}
.card{background:#fff;border:1px solid var(--line);padding:36px 32px;box-shadow:0 1px 0 var(--line)}
h1{font-size:30px;line-height:1.15;margin:0 0 6px;font-weight:normal}
.sub{color:var(--muted);margin:0 0 28px}
label{display:block;font-size:14px;color:var(--muted);margin:18px 0 6px}
input{width:100%;font:inherit;padding:12px;border:1px solid var(--line);border-radius:2px;background:#fff}
input.code{font-size:32px;letter-spacing:.35em;text-align:center;font-family:'Courier New',monospace}
canvas{width:100%;height:190px;border:1px solid var(--line);background:
 repeating-linear-gradient(0deg,transparent 0 149px,#e9e5d9 149px 150px);touch-action:none;display:block}
.tabs{display:flex;gap:0;border:1px solid var(--line);margin-top:18px}
.tabs button{flex:1;border:0;background:#fff;padding:9px;font:inherit;font-size:15px;cursor:pointer;color:var(--muted)}
.tabs button.on{background:var(--ink);color:#fff}
.pane{display:none;margin-top:14px}.pane.on{display:block}
.row{display:flex;gap:10px;margin-top:22px;align-items:center}
button.go{font:inherit;background:var(--seal);color:#fff;border:0;padding:13px 22px;cursor:pointer;border-radius:2px}
button.go:disabled{opacity:.5}
button.ghost{font:inherit;background:none;border:1px solid var(--line);padding:12px 16px;cursor:pointer;border-radius:2px}
.err{color:var(--seal);margin-top:12px;min-height:1.4em}
.fine{font-size:13px;color:var(--muted);margin-top:26px;border-top:1px solid var(--line);padding-top:14px}
.done{display:none;text-align:center;padding:30px 0}
.done b{display:block;font-size:24px;margin-bottom:8px}
</style>"""

OTP_HTML = f"""<!doctype html><html><head><meta charset=utf-8><title>Verify to sign</title>
<meta name=viewport content="width=device-width,initial-scale=1">{_STYLE}</head><body><main><div class=card>
<h1>__TITLE__</h1>
<p class=sub>Before you sign, confirm you control <b>__EMAIL__</b>. We just sent a six-digit code there.</p>
<label for=code>Verification code</label>
<input id=code class=code inputmode=numeric autocomplete=one-time-code maxlength=6 placeholder="000000" autofocus>
<div class=err id=err></div>
<div class=row><button class=go id=go>Continue</button><span style="color:var(--muted);font-size:14px">Code expires in 10 minutes.</span></div>
<p class=fine>The time you verify and the address you verify from are recorded in the document's audit trail.</p>
</div></main><script>
const go=document.getElementById('go'),code=document.getElementById('code'),err=document.getElementById('err');
async function submit(){{go.disabled=true;err.textContent='';
 const r=await fetch(location.pathname+'/otp',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{code:code.value}})}});
 if(r.ok){{location.reload();return}}
 err.textContent=(await r.json()).detail||'Something went wrong';go.disabled=false;}}
go.onclick=submit;code.onkeydown=e=>{{if(e.key==='Enter')submit()}};
</script></body></html>"""

SIGN_HTML = f"""<!doctype html><html><head><meta charset=utf-8><title>Sign</title>
<meta name=viewport content="width=device-width,initial-scale=1">{_STYLE}</head><body><main><div class=card>
<div id=form>
<h1>__TITLE__</h1>
<p class=sub>Signing as <b>__EMAIL__</b>. Envelope <code>__ENV__</code>.</p>
<div class=tabs><button class=on data-t=draw>Draw</button><button data-t=type>Type</button></div>
<div class="pane on" id=draw><canvas id=pad width=1120 height=380></canvas>
<div class=row style="margin-top:8px"><button class=ghost id=clear>Clear</button></div></div>
<div class=pane id=type><label for=name>Your full name</label><input id=name placeholder="Ada Lovelace" autocomplete=name></div>
<div class=err id=err></div>
<div class=row><button class=go id=go>Sign document</button></div>
<p class=fine>By signing you agree to sign electronically and that this signature carries the same weight as one on paper. The signature image, time, and your address are sealed into the document and cannot be altered afterward.</p>
</div>
<div class=done id=done><b>Signed.</b>You can close this page. You will get an email when everyone has signed.</div>
</div></main><script>
let mode='draw';
document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{{mode=b.dataset.t;
 document.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('on',x===b));
 document.querySelectorAll('.pane').forEach(p=>p.classList.toggle('on',p.id===mode));}});
const c=document.getElementById('pad'),ctx=c.getContext('2d');ctx.lineWidth=5;ctx.lineCap='round';ctx.lineJoin='round';ctx.strokeStyle='#141850';
let drawing=false,dirty=false;
const pos=e=>{{const r=c.getBoundingClientRect();const t=e.touches?e.touches[0]:e;return[(t.clientX-r.left)*c.width/r.width,(t.clientY-r.top)*c.height/r.height]}};
const start=e=>{{drawing=true;dirty=true;const[x,y]=pos(e);ctx.beginPath();ctx.moveTo(x,y);e.preventDefault()}};
const move=e=>{{if(!drawing)return;const[x,y]=pos(e);ctx.lineTo(x,y);ctx.stroke();e.preventDefault()}};
const end=()=>drawing=false;
c.onmousedown=start;c.onmousemove=move;c.onmouseup=end;c.onmouseleave=end;c.ontouchstart=start;c.ontouchmove=move;c.ontouchend=end;
document.getElementById('clear').onclick=()=>{{ctx.clearRect(0,0,c.width,c.height);dirty=false}};
const err=document.getElementById('err'),go=document.getElementById('go');
go.onclick=async()=>{{err.textContent='';let body;
 if(mode==='draw'){{if(!dirty){{err.textContent='Draw your signature first.';return}}body={{png:c.toDataURL('image/png').split(',')[1]}}}}
 else{{const n=document.getElementById('name').value.trim();if(!n){{err.textContent='Type your name first.';return}}body={{typed:n}}}}
 go.disabled=true;
 const r=await fetch(location.pathname,{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify(body)}});
 if(r.ok){{document.getElementById('form').style.display='none';document.getElementById('done').style.display='block'}}
 else{{err.textContent=(await r.json()).detail||'Failed';go.disabled=false}}
}};
</script></body></html>"""
