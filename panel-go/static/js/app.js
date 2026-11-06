// Paylater Monitor — клиентский JS
function postJSON(url, data, cb) {
  fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)})
    .then(r => r.text().then(t => ({ok: r.ok, status: r.status, t})))
    .then(({ok, status, t}) => {
      let j;
      try { j = JSON.parse(t); }
      catch (e) {
        alert('Ошибка сервера (' + status + '): ' + (t ? t.slice(0, 300) : 'пустой ответ'));
        return;
      }
      if (!ok) {
        alert('Ошибка (' + status + '): ' + (j.error || j.message || JSON.stringify(j)));
        return;
      }
      cb(j);
    })
    .catch(e => alert('Ошибка сети: ' + e));
}

function containerAction(server, container, action) {
  if (!confirm('Выполнить '+action+' для контейнера '+container+' на '+server+'?')) return;
  postJSON('/api/container/action', {server, container, action}, r => {
    alert(r.message || (r.success ? 'OK' : 'Ошибка'));
    location.reload();
  });
}

function vmAction(vmId, action) {
  if (!confirm('Выполнить '+action+' для ВМ '+vmId+'?')) return;
  postJSON('/api/vm/action', {vm_id: vmId, action}, r => {
    alert(r.message || (r.success ? 'OK' : 'Ошибка'));
    location.reload();
  });
}

function aiDiagnose(detection) {
  const box = document.getElementById('aiResult');
  box.style.display = 'block';
  box.innerHTML = '<p>⏳ Диагностика...</p>';
  postJSON('/api/ai/diagnose', {detection}, r => {
    let html = '<h4>Диагноз</h4><p>'+r.diagnosis+'</p>';
    html += '<p><b>Серьёзность:</b> '+r.severity+'</p>';
    if (r.remediation && r.remediation.length) {
      const safeCmds = r.remediation.filter(c => c.safe).map(c => c.command);
      window._aiCommands = safeCmds;
      html += '<h4>Команды</h4><ul>';
      r.remediation.forEach(c => {
        html += '<li><code>'+c.command+'</code> — '+c.description+(c.safe?' ✅':' ⚠️')+'</li>';
      });
      html += '</ul>';
      if (safeCmds.length) {
        html += '<button class="btn btn-primary" onclick="aiApplyWithConfirm(\''+detection.server_name+'\')">Применить безопасные ('+safeCmds.length+')</button>';
      }
    }
    if (r.recommendation) html += '<h4>Рекомендации</h4><p>'+r.recommendation+'</p>';
    box.innerHTML = html;
  });
}

// AI auto-resolve с подтверждением (пункт 10 IMPROVEMENTS.md).
function aiApplyWithConfirm(server) {
  const cmds = window._aiCommands || [];
  if (!cmds.length) { alert('Нет безопасных команд для применения'); return; }
  const summary = cmds.join('\n');
  if (!confirm('Применить ' + cmds.length + ' безопасных команд на ' + server + '?\n\n' + summary)) return;
  postJSON('/api/ai/apply', {server, commands: cmds}, r => {
    alert('Результат применения:\n' + JSON.stringify(r, null, 2));
    location.reload();
  });
}

function revokeKey(leaseId) {
  if (!confirm('Отозвать эфемерный ключ ' + leaseId + '?')) return;
  postJSON('/api/ephemeral/revoke', {lease_id: leaseId}, r => {
    alert(r.success ? 'Ключ отозван' : 'Ошибка: ' + (r.message || ''));
    location.reload();
  });
}

// Vault
document.getElementById('vaultWriteForm')?.addEventListener('submit', e => {
  e.preventDefault();
  const path = e.target.path.value;
  let data;
  try { data = JSON.parse(e.target.data.value); } catch(err) { alert('Невалидный JSON'); return; }
  postJSON('/api/vault/write', {path, data}, r => alert(r.success ? 'Записано' : 'Ошибка'));
});

// AI manual
document.getElementById('aiManualForm')?.addEventListener('submit', e => {
  e.preventDefault();
  const box = document.getElementById('aiResult');
  box.style.display = 'block';
  box.innerHTML = '<p>⏳ Диагностика...</p>';
  postJSON('/api/ai/diagnose', {server_name: e.target.server.value, query: e.target.query.value}, r => {
    box.innerHTML = '<pre>'+JSON.stringify(r, null, 2)+'</pre>';
  });
});

// Ephemeral
document.getElementById('ephemeralForm')?.addEventListener('submit', e => {
  e.preventDefault();
  postJSON('/api/ephemeral/create', {template: e.target.template.value, duration: parseInt(e.target.duration.value)}, r => {
    const box = document.getElementById('ephemeralResult');
    box.innerHTML = r.success ? '<pre>'+JSON.stringify(r.key, null, 2)+'</pre>' : '<p class="text-danger">'+r.message+'</p>';
  });
});

// JSON helper для шаблонов
function json(o) { return JSON.stringify(o); }

// Загрузка шрифта DejaVu Sans (с кириллицей) в jsPDF и установка его активным.
// Встроенные шрифты jsPDF (Helvetica/Times) — Latin-1, кириллица в PDF-отчётах
// превращалась в «козябры». DejaVu Sans имеет полную поддержку кириллицы.
function loadPdfFont(doc, family) {
  family = family || 'DejaVu';
  const base = '/static/fonts/';
  function toBase64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    // Побитовая конкатенация через chunk, чтобы не переполнить стек apply.
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }
  return Promise.all([
    fetch(base + 'DejaVuSans.ttf').then(r => r.arrayBuffer()),
    fetch(base + 'DejaVuSans-Bold.ttf').then(r => r.arrayBuffer())
  ]).then(function(arr) {
    doc.addFileToVFS('DejaVuSans.ttf', toBase64(arr[0]));
    doc.addFont('DejaVuSans.ttf', family, 'normal');
    doc.addFileToVFS('DejaVuSans-Bold.ttf', toBase64(arr[1]));
    doc.addFont('DejaVuSans-Bold.ttf', family, 'bold');
    doc.setFont(family, 'normal');
  });
}
