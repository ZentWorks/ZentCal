(()=>{
  const filters=document.querySelector('[data-email-delivery-filters]');
  const body=document.querySelector('[data-email-delivery-body]');
  if(!filters||!body)return;
  let timer;
  const en=String(window.ZentCalLang||'de').toLowerCase()==='en';
  const t={none:en?'No matching deliveries found.':'Keine passenden Zustellungen gefunden.',delivered:en?'Sent':'Versendet',failed:en?'Failed':'Fehlgeschlagen'};
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const load=()=>{
    const q=new URLSearchParams();
    const status=filters.querySelector('[name=status]').value;
    const type=filters.querySelector('[name=type]').value.trim();
    const search=filters.querySelector('[name=q]').value.trim();
    if(status)q.set('status',status); if(type)q.set('type',type); if(search)q.set('q',search);
    fetch('/ui/email-deliveries?'+q.toString(),{headers:{'Accept':'application/json'}}).then(r=>r.json()).then(j=>{
      const rows=j.data||[];
      if(!rows.length){body.innerHTML=`<tr><td colspan="6" class="muted">${t.none}</td></tr>`;return;}
      body.innerHTML=rows.map(d=>`<tr><td>${esc(d.created_at_display||d.created_at)}</td><td><code>${esc(d.type)}</code></td><td class="mono">${esc(d.recipient)}</td><td>${d.status==='success'?`<span class="status-badge good">✓ ${t.delivered}</span>`:`<span class="status-badge bad">✕ ${t.failed}</span>`}</td><td>${esc(d.attempt)}</td><td>${esc(d.error||'–')}</td></tr>`).join('');
    }).catch(()=>{});
  };
  filters.addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(load,250)});
  filters.addEventListener('change',load);
})();
