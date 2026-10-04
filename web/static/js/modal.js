(() => {
  const syncOverflow=()=>{document.body.style.overflow=document.querySelector('.modal:not([hidden])')?'hidden':''};
  const open=id=>{const m=document.getElementById(id);if(!m)return;m.hidden=false;syncOverflow();document.dispatchEvent(new CustomEvent('zentcal:modal-open',{detail:{id,modal:m}}));setTimeout(()=>m.querySelector('input:not([type=hidden]),select,button')?.focus(),0)};
  const close=m=>{m.hidden=true;syncOverflow()};
  document.addEventListener('click',e=>{const o=e.target.closest('[data-modal-open]');if(o){open(o.dataset.modalOpen);return}const c=e.target.closest('[data-modal-close]');if(c){const m=c.closest('.modal');if(m)close(m)}});
  document.addEventListener('keydown',e=>{if(e.key==='Escape'){const m=[...document.querySelectorAll('.modal:not([hidden])')].pop();if(m)close(m)}});
  window.ZentModal={open,close};
  window.ZentConfirm={ask(message){return new Promise(resolve=>{const m=document.getElementById('confirm-modal');m.querySelector('#confirm-message').textContent=message;open('confirm-modal');const yes=m.querySelector('[data-confirm-ok]');const no=[...m.querySelectorAll('[data-confirm-cancel]')];const done=v=>{yes.onclick=null;no.forEach(x=>x.onclick=null);close(m);resolve(v)};yes.onclick=()=>done(true);no.forEach(x=>x.onclick=()=>done(false))})}};
  document.querySelector('[data-copy-secret]')?.addEventListener('click',()=>window.ZentCal?.copy(document.querySelector('#secret-value')?.textContent||''));
})();
