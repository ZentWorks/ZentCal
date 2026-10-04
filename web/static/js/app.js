(() => {
  const qs=(s,r=document)=>r.querySelector(s), qsa=(s,r=document)=>[...r.querySelectorAll(s)];
  const isEN=window.ZentCalLang==='en';
  const msg=(de,en)=>isEN?en:de;
  window.ZentCal={
    csrf:()=>qs('meta[name="csrf-token"]')?.content||'',
    toast(message,type='ok'){const root=qs('#toast-root');if(!root)return;const el=document.createElement('div');el.className='toast'+(type==='error'?' error':'');el.textContent=message;root.append(el);setTimeout(()=>el.remove(),3500)},
    async copy(text){try{await navigator.clipboard.writeText(text);this.toast(msg('In Zwischenablage kopiert.','Copied to clipboard.'))}catch{this.toast(msg('Kopieren nicht möglich.','Copy failed.'),'error')}}
  };
  const flash=sessionStorage.getItem('zentcal-flash');if(flash){sessionStorage.removeItem('zentcal-flash');queueMicrotask(()=>ZentCal.toast(flash));}
  window.addEventListener('DOMContentLoaded',()=>{const id=sessionStorage.getItem('zentcal-reopen-modal');if(!id)return;sessionStorage.removeItem('zentcal-reopen-modal');window.ZentModal?.open(id)});
  qsa('[data-copy]').forEach(b=>b.addEventListener('click',()=>ZentCal.copy(b.dataset.copy)));
  qs('[data-sidebar-toggle]')?.addEventListener('click',()=>qs('.sidebar')?.classList.toggle('open'));
  document.addEventListener('click',async e=>{const b=e.target.closest('[data-delete]');if(!b)return;const confirmText=b.dataset.confirm||msg('Wirklich löschen?','Delete this item?');if(!(await window.ZentConfirm.ask(confirmText)))return;b.disabled=true;const old=b.innerHTML;b.innerHTML='<span class="spinner"></span>';try{const res=await fetch(b.dataset.delete,{method:'DELETE',headers:{'X-CSRF-Token':ZentCal.csrf(),'Accept':'application/json'}});const data=await res.json().catch(()=>({}));if(!res.ok)throw new Error(data.error||msg('Aktion fehlgeschlagen.','Action failed.'));if(data.redirect){location.href=data.redirect;return}if(data.reload){const parent=b.closest('.modal');if(parent?.id)sessionStorage.setItem('zentcal-reopen-modal',parent.id);location.reload();return}ZentCal.toast(data.message||msg('Erledigt.','Done.'))}catch(err){ZentCal.toast(err.message,'error');b.disabled=false;b.innerHTML=old}});

  const openUserEditor = row => {
    const form=qs('#edit-user-form'); if(!form||!row)return;
    form.action=`/ui/users/${encodeURIComponent(row.dataset.userId)}`;
    form.method='post';
    form.querySelector('[name="first_name"]').value=row.dataset.userFirstName||'';
    form.querySelector('[name="last_name"]').value=row.dataset.userLastName||'';
    form.querySelector('[name="email"]').value=row.dataset.userEmail||'';
    const role=form.querySelector('select[name="role"]'), status=form.querySelector('select[name="status"]');
    role.value=row.dataset.userRole||'user'; status.value=row.dataset.userStatus||'active';
    const canCreate=form.querySelector('[name="can_create_calendars"]'); if(canCreate)canCreate.checked=row.dataset.userCanCreateCalendars!=='false';
    const owner=row.dataset.userRole==='owner';
    role.disabled=owner; status.disabled=owner;
    form.querySelector('[data-owner-role]').disabled=!owner;
    form.querySelector('[data-owner-status]').disabled=!owner;
    form.querySelector('[data-owner-note]').hidden=!owner;
    const resetBtn=form.querySelector('[data-user-reset-open]');
    if(resetBtn){const unavailable=row.dataset.userAuthType==='oidc';resetBtn.hidden=unavailable;resetBtn.disabled=unavailable;resetBtn.dataset.userId=row.dataset.userId||'';}
    const deleteBtn=form.querySelector('[data-user-delete-open]');
    if(deleteBtn){const unavailable=row.dataset.userSelf==='true';deleteBtn.hidden=unavailable;deleteBtn.disabled=unavailable;deleteBtn.dataset.userId=row.dataset.userId||'';}
    for(const key of ['created','login','sync']){const el=form.querySelector(`[data-user-meta="${key}"]`);if(el)el.textContent=row.dataset['user'+key[0].toUpperCase()+key.slice(1)]||'–';}
    window.ZentModal.open('edit-user');
  };
  document.addEventListener('click',e=>{const row=e.target.closest('[data-edit-user]');if(!row||e.target.closest('button,a,input,select,textarea,label'))return;openUserEditor(row)});
  document.addEventListener('keydown',e=>{const row=e.target.closest('[data-edit-user]');if(!row||(e.key!=='Enter'&&e.key!==' '))return;e.preventDefault();openUserEditor(row)});

  const calendarColors=['#4f8cff','#7c5cff','#3fb8af','#46a66f','#d28b36','#d65c70','#5b9bd5','#9b6fd6','#2fa7c4','#7aa84b'];
  const randomizeCalendarColor=id=>{const modal=qs(`#${CSS.escape(id)}`);const input=modal?.querySelector('[data-random-calendar-color]');if(input)input.value=calendarColors[Math.floor(Math.random()*calendarColors.length)]};
  document.addEventListener('zentcal:modal-open',e=>{const id=e.detail?.id;if(id==='create-calendar'||id==='create-admin-calendar')randomizeCalendarColor(id)});
  window.addEventListener('DOMContentLoaded',()=>{const u=new URL(location.href);if(u.searchParams.get('create')==='1'&&qs('#create-calendar')){u.searchParams.delete('create');history.replaceState(null,'',u.pathname+(u.searchParams.toString()?`?${u.searchParams}`:'')+u.hash);window.ZentModal?.open('create-calendar')}});


  const openResetPassword = row => {
    const form=qs('#reset-user-password-form'); if(!form||!row)return;
    form.action=`/ui/users/${encodeURIComponent(row.dataset.userId)}/reset-password`;
    form.reset();
    form.querySelector('[data-reset-user-name]').textContent=row.dataset.userName||'';
    form.querySelector('[data-reset-user-email]').textContent=row.dataset.userEmail||'';
    {const m=qs('#edit-user');if(m)window.ZentModal.close(m);}
    window.ZentModal.open('reset-user-password');
  };
  document.addEventListener('click',e=>{
    const b=e.target.closest('[data-user-reset-open]'); if(!b)return;
    const id=b.dataset.userId; const row=id?qs(`[data-edit-user][data-user-id="${CSS.escape(id)}"]`):null;
    if(row)openResetPassword(row);
  });

  const openMemberEditor = row => {
    const form=qs('#edit-member-form'); if(!form||!row)return;
    form.querySelector('[name="user_id"]').value=row.dataset.memberId||'';
    form.querySelector('[name="role"]').value=row.dataset.memberRole||'viewer';
    form.querySelector('[data-member-name]').textContent=row.dataset.memberName||'';
    form.querySelector('[data-member-email]').textContent=row.dataset.memberEmail||'';
    window.ZentModal.open('edit-member');
  };
  document.addEventListener('click',e=>{const row=e.target.closest('[data-edit-member]');if(!row||e.target.closest('button,a,input,select,textarea,label'))return;openMemberEditor(row)});
  document.addEventListener('keydown',e=>{const row=e.target.closest('[data-edit-member]');if(!row||(e.key!=='Enter'&&e.key!==' '))return;e.preventDefault();openMemberEditor(row)});

  const openRowLink = row => { if(row?.dataset.rowHref) window.location.assign(row.dataset.rowHref); };
  document.addEventListener('click',e=>{const row=e.target.closest('[data-row-href]');if(!row||e.target.closest('button,a,input,select,textarea,label'))return;openRowLink(row)});
  document.addEventListener('keydown',e=>{const row=e.target.closest('[data-row-href]');if(!row||(e.key!=='Enter'&&e.key!==' '))return;e.preventDefault();openRowLink(row)});

  document.addEventListener('click',async e=>{const b=e.target.closest('[data-history]');if(!b)return;const box=document.querySelector('#history-list');box.innerHTML=`<div class="muted">${msg('Lade Historie…','Loading history…')}</div>`;window.ZentModal.open('history-modal');try{const res=await fetch(`/ui/events/${b.dataset.history}/history`,{headers:{'Accept':'application/json'}});const data=await res.json();if(!res.ok)throw new Error(data.error||msg('Historie konnte nicht geladen werden.','History could not be loaded.'));box.innerHTML='';for(const item of data.data){const row=document.createElement('div');row.className='history-row';const changes=(item.changes||[]).map(x=>`<li>${escapeHTML(x)}</li>`).join('');row.innerHTML=`<div><strong>v${item.version} · ${escapeHTML(item.action)}</strong><small>${escapeHTML(item.actor)} · ${new Date(item.created_at).toLocaleString()}</small></div>${changes?`<ul>${changes}</ul>`:''}`;box.append(row)}}catch(err){box.innerHTML=`<div class="alert danger">${escapeHTML(err.message)}</div>`}});
  const escapeHTML=s=>String(s).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

  const resetMarker=qs('[data-reset-user-id]');
  if(resetMarker?.dataset.resetUserId){
    const row=qs(`[data-edit-user][data-user-id="${CSS.escape(resetMarker.dataset.resetUserId)}"]`);
    if(row&&row.dataset.userAuthType!=='oidc'){history.replaceState(null,'','/users');queueMicrotask(()=>openResetPassword(row));}
  }

  document.addEventListener('click',async e=>{
    const b=e.target.closest('[data-activity-more]'); if(!b)return;
    const cursor=b.dataset.cursor; if(!cursor)return;
    b.disabled=true; const old=b.innerHTML; b.innerHTML='<span class="spinner"></span>';
    try{
      const res=await fetch(`/ui/activity?before=${encodeURIComponent(cursor)}`,{headers:{'Accept':'application/json'}});
      const data=await res.json().catch(()=>({})); if(!res.ok)throw new Error(data.error||msg('Aktivität konnte nicht geladen werden.','Activity could not be loaded.'));
      const body=qs('#activity-body');
      qs('[data-activity-empty]',body)?.remove();
      for(const item of (data.data||[])){
        const tr=document.createElement('tr'); tr.dataset.activityId=item.id;
        const cells=[item.time,item.actor,item.action,`${item.resource_type||''} ${item.resource_id||''}`.trim(),item.ip,item.request_id];
        cells.forEach((value,i)=>{const td=document.createElement('td'); if(i===2){const badge=document.createElement('span');badge.className='badge';badge.textContent=value||'';td.append(badge)}else{td.textContent=value||'';if(i===4||i===5)td.className='mono small'}tr.append(td)});
        body?.append(tr);
      }
      if(data.has_more&&data.next_cursor){b.dataset.cursor=String(data.next_cursor);b.disabled=false;b.innerHTML=old}else{b.closest('.load-more-wrap')?.remove()}
    }catch(err){window.ZentCal.toast(err.message,'error');b.disabled=false;b.innerHTML=old}
  });
})();

(() => {
  const qs=(s,r=document)=>r.querySelector(s), qsa=(s,r=document)=>[...r.querySelectorAll(s)];
  const isEN=window.ZentCalLang==='en';
  const msg=(de,en)=>isEN?en:de;
  const syncBackupProvider=()=>{
    const select=qs('[data-backup-provider-select]'); if(!select)return;
    qsa('[data-backup-provider]').forEach(el=>{el.hidden=el.dataset.backupProvider!==select.value});
  };
  const syncBackupSchedule=()=>{
    const select=qs('[data-backup-schedule]'), days=qs('[data-backup-weekdays]');
    if(!select||!days)return;
    days.hidden=select.value!=='weekly';
  };
  const syncSFTPAuth=()=>{
    const selected=qs('[name="backup_sftp_auth_method"]:checked')?.value||'password';
    qsa('[data-sftp-auth]').forEach(el=>{el.hidden=el.dataset.sftpAuth!==selected});
  };
  const encryptionReady=()=>{
    const form=qs('#backup-settings-form');
    if(!form)return false;
    if(form.dataset.encryptionSet==='true')return true;
    return (qs('[name="backup_encryption_password"]',form)?.value||'').length>=10;
  };
  const syncBackupEncryption=()=>{
    const enabled=qs('[data-backup-enabled]')?.checked===true;
    const warning=qs('[data-auto-encryption-warning]');
    if(warning)warning.hidden=!enabled||encryptionReady();
  };
  document.addEventListener('change',e=>{
    if(e.target.matches('[data-backup-provider-select]'))syncBackupProvider();
    if(e.target.matches('[data-backup-schedule]'))syncBackupSchedule();
    if(e.target.matches('[name="backup_sftp_auth_method"]'))syncSFTPAuth();
    if(e.target.matches('[data-backup-enabled]'))syncBackupEncryption();
  });
  document.addEventListener('input',e=>{if(e.target.matches('[name="backup_encryption_password"]'))syncBackupEncryption()});
  document.addEventListener('submit',e=>{
    const form=e.target.closest('#backup-settings-form'); if(!form)return;
    if(qs('[data-backup-enabled]',form)?.checked&&!encryptionReady()){
      e.preventDefault(); e.stopImmediatePropagation();
      const err=qs('[data-form-error]',form);
      const text=msg('Für automatische Backups muss zuerst ein Verschlüsselungspasswort mit mindestens 10 Zeichen festgelegt werden.','Set an encryption password with at least 10 characters before enabling automatic backups.');
      if(err){err.textContent=text;err.classList.add('show');err.scrollIntoView({block:'nearest'})}else window.ZentCal.toast(text,'error');
    }
  });
  syncBackupProvider(); syncBackupSchedule(); syncSFTPAuth(); syncBackupEncryption();

  document.addEventListener('click',e=>{
    const b=e.target.closest('[data-backup-verify]'); if(!b)return;
    const form=qs('#verify-backup-form'); if(!form)return;
    form.action=`/ui/backups/${encodeURIComponent(b.dataset.backupVerify)}/verify`;
    form.reset(); window.ZentModal.open('verify-backup');
  });
  const backupAuthType=qs('[data-backup-auth-type]')?.dataset.backupAuthType||'';
  const openBackupReauth=(action,target)=>{
    const form=qs('#backup-reauth-form'); if(!form)return;
    form.reset(); form.querySelector('[name="action"]').value=action; form.querySelector('[name="target"]').value=target||'';
    const title=qs('[data-backup-reauth-title]',form.closest('.modal')), text=qs('[data-backup-reauth-text]',form.closest('.modal'));
    const labels={restore:[msg('Backup wiederherstellen','Restore backup'),msg('Backup wirklich wiederherstellen?','Really restore this backup?')],delete:[msg('Backup löschen','Delete backup'),msg('Backup wirklich löschen?','Really delete this backup?')],upload_restore:[msg('Backup hochladen & wiederherstellen','Upload and restore backup'),msg('Backup wirklich hochladen und wiederherstellen?','Really upload and restore a backup?')]};
    const copy=labels[action]||[msg('Aktion bestätigen','Confirm action'),msg('Aktion wirklich ausführen?','Really perform this action?')];
    if(title)title.textContent=copy[0]; if(text)text.textContent=copy[1]; window.ZentModal.open('backup-reauth');
  };
  const openRestoreBackup=id=>{const form=qs('#restore-backup-form');if(!form)return;form.action=`/ui/backups/${encodeURIComponent(id)}/restore`;form.reset();window.ZentModal.open('restore-backup')};
  const openDeleteBackup=id=>{const form=qs('#delete-backup-form');if(!form)return;form.reset();form.querySelector('[name="backup_id"]').value=id;window.ZentModal.open('delete-backup')};
  document.addEventListener('click',e=>{
    const b=e.target.closest('[data-backup-restore]'); if(!b)return;
    const id=b.dataset.backupRestore; if(backupAuthType==='oidc')openBackupReauth('restore',id);else openRestoreBackup(id);
  });
  document.addEventListener('click',e=>{
    const b=e.target.closest('[data-backup-delete]'); if(!b)return;
    const id=b.dataset.backupDelete; if(backupAuthType==='oidc')openBackupReauth('delete',id);else openDeleteBackup(id);
  });
  document.addEventListener('click',e=>{
    const b=e.target.closest('[data-backup-upload-restore]'); if(!b)return;
    if(backupAuthType==='oidc')openBackupReauth('upload_restore','upload');else{qs('#upload-restore-form')?.reset();window.ZentModal.open('upload-restore')}
  });
  document.addEventListener('submit',async e=>{
    const form=e.target.closest('#delete-backup-form'); if(!form)return;
    e.preventDefault(); const id=form.querySelector('[name="backup_id"]')?.value; if(!id)return;
    const submit=e.submitter, old=submit?.innerHTML; if(submit){submit.disabled=true;submit.innerHTML='<span class="spinner"></span>'+msg('Lösche…','Deleting…')}
    const errBox=qs('[data-form-error]',form); if(errBox){errBox.textContent='';errBox.classList.remove('show')}
    try{
      const body=new URLSearchParams(new FormData(form)); body.delete('backup_id');
      const res=await fetch(`/ui/backups/${encodeURIComponent(id)}/delete`,{method:'POST',body,headers:{'X-CSRF-Token':window.ZentCal.csrf(),'Accept':'application/json','Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'}});
      const data=await res.json().catch(()=>({})); if(!res.ok)throw new Error(data.error||msg('Backup konnte nicht gelöscht werden.','Backup could not be deleted.'));
      sessionStorage.setItem('zentcal-flash',data.message||msg('Backup gelöscht.','Backup deleted.')); location.href='/backups';
    }catch(err){if(errBox){errBox.textContent=err.message;errBox.classList.add('show')}else window.ZentCal.toast(err.message,'error');if(submit){submit.disabled=false;submit.innerHTML=old}}
  });
  window.addEventListener('DOMContentLoaded',()=>{
    const marker=qs('[data-backup-reauth-return]'); if(!marker)return; const action=marker.dataset.action,target=marker.dataset.target;
    if(!action)return; history.replaceState(null,'','/backups');
    if(action==='restore'&&target)openRestoreBackup(target); else if(action==='delete'&&target)openDeleteBackup(target); else if(action==='upload_restore'){qs('#upload-restore-form')?.reset();window.ZentModal.open('upload-restore')}
  });
  document.addEventListener('click',e=>{
    const b=e.target.closest('[data-backup-test]'); if(!b)return;
    const form=qs('#backup-settings-form'); if(!form)return;
    const oldAction=form.action; form.action='/ui/backups/test';
    form.requestSubmit(); queueMicrotask(()=>{form.action=oldAction});
  });

  const live=qs('[data-backup-live]'), liveTitle=qs('[data-backup-live-title]'), liveStage=qs('[data-backup-live-stage]'), runBtn=qs('[data-backup-run]');
  const manual=qs('[data-encryption-ready]');
  const manualEncryptionReady=manual?.dataset.encryptionReady==='true';
  let observedRunning=false, reloadAfterFinish=false;
  const setRunState=running=>{if(!runBtn)return;runBtn.disabled=running||!manualEncryptionReady;runBtn.innerHTML=running?`<span class="spinner"></span>${msg('Backup läuft…','Backup running…')}`:msg('Backup jetzt','Backup now')};
  const refreshBackupStatus=async()=>{
    if(!live)return;
    try{
      const res=await fetch('/ui/backups/status',{headers:{'X-CSRF-Token':window.ZentCal.csrf(),'Accept':'application/json'}});
      const data=await res.json().catch(()=>({})); if(!res.ok)return;
      if(data.running){observedRunning=true;live.hidden=false;setRunState(true);liveTitle.textContent=msg('Backup läuft','Backup running');liveStage.textContent=data.current?.stage_label||msg('Vorbereitung…','Preparing…');return}
      setRunState(false);
      if(observedRunning){
        observedRunning=false;
        const failed=data.current?.status==='failed'; live.hidden=false;
        liveTitle.textContent=failed?msg('Backup fehlgeschlagen','Backup failed'):msg('Backup abgeschlossen','Backup completed');
        liveStage.textContent=failed?(data.current?.error||msg('Unbekannter Fehler.','Unknown error.')):msg('Die Backup-Liste wird aktualisiert.','Refreshing backup list.');
        if(!reloadAfterFinish){reloadAfterFinish=true;setTimeout(()=>location.reload(),900)}
      } else { live.hidden=true; }
    }catch{}
  };
  if(live){refreshBackupStatus();setInterval(refreshBackupStatus,2500)}

  document.addEventListener('click',async e=>{
    const b=e.target.closest('[data-backup-run]'); if(!b)return;
    if(!manualEncryptionReady){window.ZentCal.toast(msg('Bitte zuerst ein Verschlüsselungspasswort festlegen und speichern.','Set and save an encryption password first.'),'error');return}
    if(!(await window.ZentConfirm.ask(msg('Jetzt ein verschlüsseltes Backup erstellen?','Create an encrypted backup now?'))))return;
    setRunState(true); if(live){live.hidden=false;liveTitle.textContent=msg('Backup wird gestartet','Starting backup');liveStage.textContent=msg('Vorbereitung…','Preparing…')}
    try{
      const res=await fetch('/ui/backups/run',{method:'POST',headers:{'X-CSRF-Token':window.ZentCal.csrf(),'Accept':'application/json'}});
      const data=await res.json().catch(()=>({}));if(!res.ok)throw new Error(data.error||msg('Backup konnte nicht gestartet werden.','Backup could not be started.'));
      window.ZentCal.toast(data.message||msg('Backup gestartet.','Backup started.')); observedRunning=true; setTimeout(refreshBackupStatus,450);
    }catch(err){window.ZentCal.toast(err.message,'error');setRunState(false);if(live)live.hidden=true}
  });
})();

// Mail-template editor: keep one template visible while all fields stay in the
// same form so saving remains atomic across DE/EN and every notification type.
document.addEventListener('click',e=>{
  const tab=e.target.closest('[data-mail-template-tab]');
  if(!tab)return;
  const root=tab.closest('.mail-template-form');
  if(!root)return;
  const key=tab.dataset.mailTemplateTab;
  root.querySelectorAll('[data-mail-template-tab]').forEach(x=>x.classList.toggle('active',x===tab));
  root.querySelectorAll('[data-mail-template-panel]').forEach(panel=>{
    const active=panel.dataset.mailTemplatePanel===key;
    panel.hidden=!active;
    panel.classList.toggle('active',active);
  });
});
