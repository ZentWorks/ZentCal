(() => {
  const qs=(s,r=document)=>r.querySelector(s);
  const lang=window.ZentCalLang==='en'?'en':'de';
  const msg=(de,en)=>lang==='en'?en:de;
  const debounce=(fn,ms=280)=>{let t;return(...a)=>{clearTimeout(t);t=setTimeout(()=>fn(...a),ms)}};
  const fetchJSON=async url=>{const res=await fetch(url,{headers:{Accept:'application/json'}});const data=await res.json().catch(()=>({}));if(!res.ok)throw new Error(data.error||msg('Suche fehlgeschlagen.','Search failed.'));return data};
  const td=(text,cls='')=>{const el=document.createElement('td');el.textContent=text??'';if(cls)el.className=cls;return el};
  const empty=(body,cols,text)=>{body.textContent='';const tr=document.createElement('tr'),cell=td(text,'empty-cell');cell.colSpan=cols;tr.append(cell);body.append(tr)};

  const usersInput=qs('[data-user-search]'), usersBody=qs('#users-body');
  if(usersInput&&usersBody){
    const ssoEnabled=usersBody.dataset.ssoEnabled==='true', userCols=ssoEnabled?7:6;
    const render=items=>{
      if(!items.length){empty(usersBody,userCols,msg('Keine Benutzer gefunden.','No users found.'));return}
      usersBody.textContent='';
      for(const u of items){
        const tr=document.createElement('tr');tr.className='clickable-row';tr.tabIndex=0;tr.setAttribute('role','button');tr.setAttribute('aria-label',`${u.name} ${msg('bearbeiten','edit')}`);tr.dataset.editUser='';
        Object.assign(tr.dataset,{userId:u.id||'',userName:u.name||'',userFirstName:u.first_name||'',userLastName:u.last_name||'',userEmail:u.email||'',userRole:u.role||'user',userStatus:u.status||'active',userAuthType:u.auth_type||'local',userCanCreateCalendars:u.can_create_calendars===false?'false':'true',userSelf:u.self?'true':'false',userCreated:u.created||'–',userLogin:u.last_login||'–',userSync:u.last_sync||'–'});
        const user=td('');const wrap=document.createElement('div');wrap.className='user-cell';const av=document.createElement('span');av.className='avatar';av.textContent=(u.name||u.email||'?').trim().charAt(0).toUpperCase();const detail=document.createElement('div');const strong=document.createElement('strong');strong.textContent=u.name||'–';const small=document.createElement('small');small.textContent=u.email||'';detail.append(strong,small);wrap.append(av,detail);user.append(wrap);tr.append(user,td(u.role||''),td(String(u.additional_calendars??0)));if(ssoEnabled){const cell=td('');const mark=document.createElement('span');const linked=u.auth_type==='oidc';mark.className=`sso-status ${linked?'yes':'no'}`;mark.textContent=linked?'✓':'×';mark.title=linked?msg('SSO verbunden','SSO linked'):msg('Nicht mit SSO verbunden','Not linked to SSO');cell.append(mark);tr.append(cell)}tr.append(td(u.status||''),td(u.last_login||'–'),td(u.last_sync||'–'));usersBody.append(tr)
      }
    };
    const run=debounce(async()=>{try{const data=await fetchJSON(`/ui/users/search?q=${encodeURIComponent(usersInput.value.trim())}`);render(data.data||[])}catch(e){window.ZentCal?.toast(e.message,'error')}});
    usersInput.addEventListener('input',run);
  }

  const calInput=qs('[data-admin-calendar-search]'), calBody=qs('#admin-calendar-body');
  if(calInput&&calBody){
    const render=items=>{
      if(!items.length){empty(calBody,5,msg('Keine Kalender gefunden.','No calendars found.'));return}
      calBody.textContent='';
      for(const c of items){
        const tr=document.createElement('tr');tr.className='clickable-row';tr.tabIndex=0;tr.setAttribute('role','button');tr.dataset.rowHref=`/calendars/${encodeURIComponent(c.id)}?admin=1`;
        const name=td('');const wrap=document.createElement('div');wrap.className='calendar-name';const sw=document.createElement('span');sw.className='calendar-dot';sw.style.background=c.color||'#4f8cff';const st=document.createElement('strong');st.textContent=c.name||'–';wrap.append(sw,st);name.append(wrap);
        const typeLabel=c.type==='resource'?msg('Ressource','Resource'):msg('Kalender','Calendar');const ownerLabel=c.needs_owner?msg('Temporäre Verwaltung – Owner fehlt','Temporary administration – Owner missing'):(c.owner_names||'–');tr.append(name,td(typeLabel),td(ownerLabel),td(String(c.members??0)),td(c.can_read_events===false?'–':String(c.events??0)));calBody.append(tr)
      }
    };
    const run=debounce(async()=>{try{const data=await fetchJSON(`/ui/admin-calendars/search?q=${encodeURIComponent(calInput.value.trim())}`);render(data.data||[])}catch(e){window.ZentCal?.toast(e.message,'error')}});
    calInput.addEventListener('input',run);
  }

  const activityBody=qs('#activity-body'), activitySearch=qs('[data-activity-search]'), activityType=qs('[data-activity-type]'), activityDays=qs('[data-activity-days]');
  if(activityBody&&(activitySearch||activityType||activityDays)){
    const render=items=>{
      document.querySelector('.load-more-wrap')?.setAttribute('hidden','hidden');
      if(!items.length){empty(activityBody,6,msg('Keine Aktivitäten gefunden.','No activity found.'));return}
      activityBody.textContent='';
      for(const a of items){const tr=document.createElement('tr');tr.dataset.activityId=a.id;tr.append(td(a.time||''),td(a.actor||''));const action=td('');const badge=document.createElement('span');badge.className='badge';badge.textContent=a.action||'';action.append(badge);tr.append(action,td(`${a.resource_type||''} ${a.resource_id||''}`.trim()),td(a.ip||'','mono small'),td(a.request_id||'','mono small'));activityBody.append(tr)}
    };
    const run=debounce(async()=>{try{const p=new URLSearchParams({q:activitySearch?.value.trim()||'',type:activityType?.value||'',days:activityDays?.value||'60'});const data=await fetchJSON(`/ui/activity/search?${p}`);render(data.data||[])}catch(e){window.ZentCal?.toast(e.message,'error')}});
    activitySearch?.addEventListener('input',run);activityType?.addEventListener('change',run);activityDays?.addEventListener('change',run);
  }

  const deleteButton=qs('[data-user-delete-open]'), deleteForm=qs('#delete-user-form');
  if(deleteButton&&deleteForm){
    const syncAction=()=>{const transfer=deleteForm.querySelector('[name="calendar_action"]:checked')?.value==='transfer';const box=deleteForm.querySelector('[data-delete-new-owner]'), sel=deleteForm.querySelector('[name="new_owner_id"]');if(box)box.hidden=!transfer;if(sel){sel.disabled=!transfer;sel.required=transfer}};
    deleteForm.addEventListener('change',e=>{if(e.target.name==='calendar_action')syncAction()});
    deleteButton.addEventListener('click',async()=>{
      const id=deleteButton.dataset.userId;if(!id)return;
      try{
        const data=await fetchJSON(`/ui/users/${encodeURIComponent(id)}/delete-info`), info=data.data||{};
        deleteForm.action=`/ui/users/${encodeURIComponent(id)}/delete`;
        deleteForm.querySelector('[data-delete-user-name]').textContent=info.name||'';deleteForm.querySelector('[data-delete-user-email]').textContent=info.email||'';
        const owned=info.owned_calendars||[], ownedBlock=deleteForm.querySelector('[data-delete-owned-block]'), simple=deleteForm.querySelector('[data-delete-simple-block]'), list=deleteForm.querySelector('[data-delete-owned-list]');
        ownedBlock.hidden=!owned.length;simple.hidden=!!owned.length;list.textContent='';
        for(const c of owned){const item=document.createElement('div');item.className='delete-owned-item';item.textContent=c.name||c.id;list.append(item)}
        const sel=deleteForm.querySelector('[name="new_owner_id"]');sel.textContent='';for(const u of info.replacement_users||[]){const o=document.createElement('option');o.value=u.id;o.textContent=`${u.name} · ${u.email}`;sel.append(o)}
        const transfer=deleteForm.querySelector('[name="calendar_action"][value="transfer"]');if(transfer)transfer.checked=true;syncAction();
        const edit=qs('#edit-user');if(edit)window.ZentModal?.close(edit);window.ZentModal?.open('delete-user');
      }catch(e){window.ZentCal?.toast(e.message,'error')}
    });
  }
})();
