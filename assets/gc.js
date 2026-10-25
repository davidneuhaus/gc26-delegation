/* Client-side decryption: PBKDF2-SHA256 (600000 it.) -> AES-256-GCM. No password or hash stored. */
(function(){
var SALT='Ygx7IMPsT+rbErL6f2kAdA==',ITER=600000,SK='gc26k';
function b64d(s){var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u}
function b64e(u){var s='';for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s)}
function getRaw(){try{var v=sessionStorage.getItem(SK);return v?b64d(v):null}catch(e){return null}}
function imp(raw){return crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt'])}
function derive(pw){return crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']).then(function(b){return crypto.subtle.deriveBits({name:'PBKDF2',salt:b64d(SALT),iterations:ITER,hash:'SHA-256'},b,256)}).then(function(x){return new Uint8Array(x)})}
function dec(key,u){return crypto.subtle.decrypt({name:'AES-GCM',iv:u.slice(0,12)},key,u.slice(12))}
var payload=document.getElementById('gc-payload');
if(payload){
  var data=b64d(payload.textContent.trim());
  var show=function(raw){return imp(raw).then(function(k){return dec(k,data)}).then(function(pt){
      try{sessionStorage.setItem(SK,b64e(raw))}catch(e){}
      var html=new TextDecoder().decode(pt);var nd=new DOMParser().parseFromString(html,'text/html');
      var root=document.adoptNode(nd.documentElement);document.replaceChild(root,document.documentElement);
      root.querySelectorAll('script').forEach(function(o){var n=document.createElement('script');for(var i=0;i<o.attributes.length;i++)n.setAttribute(o.attributes[i].name,o.attributes[i].value);if(!o.src)n.textContent=o.textContent;else n.async=false;o.parentNode.replaceChild(n,o)});
      if(location.hash){try{var el=document.getElementById(decodeURIComponent(location.hash.slice(1)));if(el){if(el.tagName==='DETAILS')el.open=true;setTimeout(function(){el.scrollIntoView()},50)}}catch(e){}}
    })};
  var unhide=function(){document.documentElement.className='';};
  var raw=getRaw();
  if(raw){show(raw).catch(function(){try{sessionStorage.removeItem(SK)}catch(e){}unhide()})}
  var f=document.getElementById('gc-form');
  f.addEventListener('submit',function(e){e.preventDefault();
    var err=document.getElementById('gc-err'),btn=document.getElementById('gc-btn'),inp=document.getElementById('password');
    err.hidden=true;btn.disabled=true;var t=btn.textContent;btn.textContent='Opening…';
    derive(inp.value).then(show).catch(function(){err.hidden=false;btn.disabled=false;btn.textContent=t;inp.value='';inp.focus()});
  });
  return;
}
/* Unlocked page: decrypt images and downloads */
var rawk=getRaw();
if(!rawk){location.replace('index.html');return}
var kp=imp(rawk);
function fetchDec(url,type){return kp.then(function(k){return fetch(url).then(function(r){if(!r.ok)throw new Error(r.status);return r.arrayBuffer()}).then(function(b){return dec(k,new Uint8Array(b))})}).then(function(pt){return new Blob([pt],{type:type})})}
var imgs=document.querySelectorAll('img[data-gc-src]');
var cache={};
imgs.forEach(function(im){var u=im.getAttribute('data-gc-src');
  (cache[u]=cache[u]||fetchDec(u,im.getAttribute('data-gc-type')).then(function(b){return URL.createObjectURL(b)})).then(function(o){im.src=o}).catch(function(e){console.warn('img',u,e)})});
document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[data-gc-file]');if(!a)return;e.preventDefault();
  var name=a.getAttribute('download')||'download.pdf';a.style.opacity='.6';
  fetchDec(a.getAttribute('data-gc-file'),a.getAttribute('data-gc-type')).then(function(b){var o=URL.createObjectURL(b);var t=document.createElement('a');t.href=o;t.download=name;document.body.appendChild(t);t.click();t.remove();setTimeout(function(){URL.revokeObjectURL(o)},60000);a.style.opacity=''})
  .catch(function(err){a.style.opacity='';alert('Download failed – please reload the page and try again.')})});
document.querySelectorAll('form[data-gc-logout]').forEach(function(f){f.addEventListener('submit',function(){try{sessionStorage.removeItem(SK)}catch(e){}})});
})();
