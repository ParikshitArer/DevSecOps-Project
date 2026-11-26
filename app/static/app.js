(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const state = {
    token: sessionStorage.getItem('securenotes_access_token') || '',
    username: sessionStorage.getItem('securenotes_username') || '',
    notes: [],
    selectedId: null,
    isNew: false,
    mode: 'login',
    activeView: 'notes',
    searchTimer: null,
    toastTimer: null
  };

  function setMessage(message, type = '') {
    const el = $('authMessage');
    el.textContent = message || '';
    el.className = `form-message ${type}`.trim();
  }

  function toast(message, type = 'success') {
    const region = $('toastRegion');
    const item = document.createElement('div');
    item.className = `toast ${type}`;
    item.textContent = message;
    region.appendChild(item);
    window.setTimeout(() => item.remove(), 3600);
  }

  function errorText(data, fallback) {
    if (!data) return fallback;
    if (typeof data.error === 'string') {
      let message = data.error;
      if (data.fields && typeof data.fields === 'object') {
        const details = Object.entries(data.fields).map(([key, value]) => `${key}: ${value}`).join(' · ');
        if (details) message += ` — ${details}`;
      }
      return message;
    }
    if (typeof data.message === 'string') return data.message;
    return fallback;
  }

  async function api(path, options = {}) {
    const headers = { Accept: 'application/json', ...(options.headers || {}) };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    if (state.token && options.auth !== false) headers.Authorization = `Bearer ${state.token}`;

    let response;
    try {
      response = await fetch(path, {
        method: options.method || 'GET',
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
        cache: 'no-store'
      });
    } catch (err) {
      throw new Error('Could not reach the SecureNotes API. Check the server and network connection.');
    }

    let data = null;
    if (response.status !== 204) {
      const raw = await response.text();
      if (raw) {
        try { data = JSON.parse(raw); }
        catch { data = { message: raw.slice(0, 300) }; }
      }
    }

    if (!response.ok) {
      if (response.status === 401 && state.token) handleUnauthorized();
      const fallback = `Request failed (${response.status})`;
      throw new Error(errorText(data, fallback));
    }
    return data;
  }

  function showAuth() {
    $('appView').classList.add('hidden');
    $('authView').classList.remove('hidden');
  }

  function showApp() {
    $('authView').classList.add('hidden');
    $('appView').classList.remove('hidden');
    $('currentUsername').textContent = state.username || 'User';
    $('userAvatar').textContent = (state.username || 'U').slice(0, 1).toUpperCase();
    $('breadcrumbCurrent').textContent = 'My notes';
    showView('notes');
    checkHealth();
    loadNotes();
  }

  function clearSession() {
    state.token = '';
    state.username = '';
    state.notes = [];
    state.selectedId = null;
    state.isNew = false;
    sessionStorage.removeItem('securenotes_access_token');
    sessionStorage.removeItem('securenotes_username');
  }

  function handleUnauthorized() {
    clearSession();
    showAuth();
    setMessage('Your session has expired. Please sign in again.', 'error');
  }

  function setAuthMode(mode) {
    state.mode = mode;
    const register = mode === 'register';
    $('loginTab').classList.toggle('active', !register);
    $('registerTab').classList.toggle('active', register);
    $('loginTab').setAttribute('aria-selected', String(!register));
    $('registerTab').setAttribute('aria-selected', String(register));
    $('authTitle').textContent = register ? 'Create your space' : 'Welcome back';
    $('authSubtitle').textContent = register ? 'Set up an account to keep your notes private.' : 'Sign in to pick up where you left off.';
    $('authSubmit').firstElementChild.textContent = register ? 'Create account' : 'Sign in securely';
    $('passwordHint').textContent = register ? 'Create a strong password' : 'Your account password';
    $('registerRules').classList.toggle('hidden', !register);
    $('authPassword').setAttribute('autocomplete', register ? 'new-password' : 'current-password');
    setMessage('');
  }

  async function checkHealth() {
    const targets = [
      [$('authApiStatus'), $('authApiText')],
      [$('sidebarApiDot'), $('sidebarApiText')],
      [$('topApiDot'), $('topApiText')]
    ];
    try {
      const result = await api('/healthz', { auth: false });
      if (!result || result.status !== 'ok') throw new Error('Unexpected health response');
      targets.forEach(([dot, text]) => {
        dot.className = 'status-dot status-online';
        text.textContent = dot === $('authApiStatus') ? 'Service online' : 'Connected and healthy';
      });
    } catch (_) {
      targets.forEach(([dot, text]) => {
        dot.className = 'status-dot status-offline';
        text.textContent = 'API unavailable';
      });
    }
  }

  function formatDate(value) {
    if (!value) return 'Just now';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return 'Recently';
    return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' }).format(date);
  }

  function noteSnippet(note) {
    const body = (note.body || '').replace(/\s+/g, ' ').trim();
    return body || 'No additional details';
  }

  function renderNotes() {
    const list = $('notesList');
    list.replaceChildren();
    $('notesTotal').textContent = String(state.notes.length);
    $('navNoteCount').textContent = String(state.notes.length);

    if (!state.notes.length) {
      const empty = document.createElement('div');
      empty.className = 'list-empty';
      const title = document.createElement('b');
      title.textContent = 'No notes found';
      const description = document.createElement('span');
      description.textContent = $('noteSearch').value ? 'Try another search term.' : 'Create a note and it will appear here.';
      empty.append(title, description);
      list.appendChild(empty);
      return;
    }

    state.notes.forEach((note) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `note-item ${String(note.id) === String(state.selectedId) && !state.isNew ? 'active' : ''}`;
      button.addEventListener('click', () => selectNote(note));

      const top = document.createElement('div');
      top.className = 'note-item-top';
      const marker = document.createElement('span');
      marker.className = 'note-item-marker';
      const title = document.createElement('span');
      title.className = 'note-item-title';
      title.textContent = note.title || 'Untitled note';
      const date = document.createElement('span');
      date.className = 'note-item-date';
      date.textContent = formatDate(note.created_at);
      top.append(marker, title, date);

      const preview = document.createElement('div');
      preview.className = 'note-item-preview';
      preview.textContent = noteSnippet(note);
      button.append(top, preview);
      list.appendChild(button);
    });
  }

  async function loadNotes(selectId = null) {
    const list = $('notesList');
    list.innerHTML = '<div class="list-skeleton"><span></span><span></span><span></span></div>';
    const query = $('noteSearch').value.trim();
    const params = new URLSearchParams({ page: '1', per_page: '50' });
    if (query) params.set('q', query);

    try {
      const result = await api(`/api/notes?${params.toString()}`);
      state.notes = Array.isArray(result.items) ? result.items : [];
      renderNotes();

      if (selectId !== null) {
        const found = state.notes.find((note) => String(note.id) === String(selectId));
        if (found) selectNote(found);
        else showEmptyEditor();
      } else if (state.selectedId !== null && !state.isNew) {
        const current = state.notes.find((note) => String(note.id) === String(state.selectedId));
        if (current) selectNote(current);
        else showEmptyEditor();
      } else if (!state.notes.length && !state.isNew) {
        showEmptyEditor();
      }
    } catch (err) {
      list.replaceChildren();
      const empty = document.createElement('div');
      empty.className = 'list-empty';
      const title = document.createElement('b');
      title.textContent = 'Could not load notes';
      const detail = document.createElement('span');
      detail.textContent = err.message;
      empty.append(title, detail);
      list.appendChild(empty);
      toast(err.message, 'error');
    }
  }

  function showEmptyEditor() {
    state.selectedId = null;
    state.isNew = false;
    $('editorEmpty').classList.remove('hidden');
    $('editorContent').classList.add('hidden');
    renderNotes();
  }

  function startNewNote() {
    state.selectedId = null;
    state.isNew = true;
    $('editorEmpty').classList.add('hidden');
    $('editorContent').classList.remove('hidden');
    $('editorStateText').textContent = 'NEW NOTE';
    $('savedDate').textContent = 'Unsaved draft';
    $('noteTitle').value = '';
    $('noteBody').value = '';
    $('bodyCount').textContent = '0 / 2,000';
    $('deleteNoteButton').classList.add('hidden');
    $('saveNoteButton').innerHTML = 'Create note <span>→</span>';
    $('noteTitle').focus();
    renderNotes();
  }

  function selectNote(note) {
    state.selectedId = note.id;
    state.isNew = false;
    $('editorEmpty').classList.add('hidden');
    $('editorContent').classList.remove('hidden');
    $('editorStateText').textContent = 'SAVED NOTE';
    $('savedDate').textContent = `Created ${formatDate(note.created_at)}`;
    $('noteTitle').value = note.title || '';
    $('noteBody').value = note.body || '';
    $('bodyCount').textContent = `${$('noteBody').value.length.toLocaleString()} / 2,000`;
    $('deleteNoteButton').classList.remove('hidden');
    $('saveNoteButton').innerHTML = 'Save changes <span>→</span>';
    renderNotes();
  }

  async function saveNote() {
    const title = $('noteTitle').value.trim();
    const body = $('noteBody').value;
    if (!title || title.length > 100) {
      toast('A title between 1 and 100 characters is required.', 'error');
      $('noteTitle').focus();
      return;
    }
    if (body.length > 2000) {
      toast('Note body must be 2,000 characters or fewer.', 'error');
      return;
    }

    const button = $('saveNoteButton');
    button.classList.add('is-busy');
    try {
      let result;
      if (state.isNew) {
        result = await api('/api/notes', { method: 'POST', body: { title, body } });
        toast('Your note has been created.');
      } else {
        result = await api(`/api/notes/${encodeURIComponent(state.selectedId)}`, { method: 'PUT', body: { title, body } });
        toast('Your changes have been saved.');
      }
      await loadNotes(result && result.id !== undefined ? result.id : null);
      if (result && result.id !== undefined) selectNote(result);
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      button.classList.remove('is-busy');
    }
  }

  async function deleteNote() {
    if (state.selectedId === null || state.isNew) return;
    if (!window.confirm('Delete this note? This cannot be undone.')) return;
    try {
      await api(`/api/notes/${encodeURIComponent(state.selectedId)}`, { method: 'DELETE' });
      toast('Note deleted.');
      state.selectedId = null;
      await loadNotes();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  function showView(view) {
    state.activeView = view;
    const isAdmin = view === 'admin';
    $('notesView').classList.toggle('hidden', isAdmin);
    $('adminView').classList.toggle('hidden', !isAdmin);
    $('notesNav').classList.toggle('active', !isAdmin);
    $('adminNav').classList.toggle('active', isAdmin);
    $('breadcrumbCurrent').textContent = isAdmin ? 'Admin console' : 'My notes';
    if (isAdmin) loadAdmin();
  }

  async function loadAdmin() {
    $('adminDenied').classList.add('hidden');
    $('adminContent').classList.add('hidden');
    $('refreshAdminButton').classList.add('is-busy');
    try {
      const [stats, users] = await Promise.all([
        api('/api/admin/stats'),
        api('/api/admin/users')
      ]);
      $('adminUsersCount').textContent = String(stats.users ?? '—');
      $('adminNotesCount').textContent = String(stats.notes ?? '—');
      renderAdminUsers(Array.isArray(users.items) ? users.items : []);
      $('adminContent').classList.remove('hidden');
    } catch (err) {
      if (/forbidden|authentication|required/i.test(err.message)) {
        $('adminDenied').classList.remove('hidden');
      } else {
        toast(err.message, 'error');
        $('adminDenied').classList.remove('hidden');
      }
    } finally {
      $('refreshAdminButton').classList.remove('is-busy');
    }
  }

  function renderAdminUsers(users) {
    const tbody = $('adminUsersTable');
    tbody.replaceChildren();
    if (!users.length) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 4;
      cell.className = 'table-placeholder';
      cell.textContent = 'No registered users found.';
      row.appendChild(cell);
      tbody.appendChild(row);
      return;
    }
    users.forEach((user) => {
      const row = document.createElement('tr');
      const nameCell = document.createElement('td');
      const nameWrap = document.createElement('div');
      nameWrap.className = 'user-cell';
      const avatar = document.createElement('span');
      avatar.className = 'user-table-avatar';
      avatar.textContent = (user.username || '?').slice(0, 1).toUpperCase();
      const username = document.createElement('span');
      username.textContent = user.username || 'Unknown';
      nameWrap.append(avatar, username);
      nameCell.appendChild(nameWrap);
      const roleCell = document.createElement('td');
      const role = document.createElement('span');
      role.className = `role-pill ${user.role === 'admin' ? 'admin' : ''}`;
      role.textContent = user.role || 'user';
      roleCell.appendChild(role);
      const idCell = document.createElement('td');
      idCell.textContent = String(user.id ?? '—');
      const dateCell = document.createElement('td');
      dateCell.textContent = formatDate(user.created_at);
      row.append(nameCell, roleCell, idCell, dateCell);
      tbody.appendChild(row);
    });
  }

  $('loginTab').addEventListener('click', () => setAuthMode('login'));
  $('registerTab').addEventListener('click', () => setAuthMode('register'));
  $('togglePassword').addEventListener('click', () => {
    const input = $('authPassword');
    const reveal = input.type === 'password';
    input.type = reveal ? 'text' : 'password';
    $('togglePassword').textContent = reveal ? 'Hide' : 'Show';
    $('togglePassword').setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
  });

  $('authForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const username = $('authUsername').value.trim();
    const password = $('authPassword').value;
    const register = state.mode === 'register';
    const submit = $('authSubmit');

    if (register) {
      if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) {
        setMessage('Username must be 3–32 characters using letters, numbers or underscores.', 'error');
        return;
      }
      if (password.length < 10 || password.length > 128 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
        setMessage('Password must be 10–128 characters and include uppercase, lowercase and a number.', 'error');
        return;
      }
    }

    submit.classList.add('is-busy');
    setMessage(register ? 'Creating your account…' : 'Signing you in…');
    try {
      if (register) {
        await api('/api/auth/register', { method: 'POST', body: { username, password }, auth: false });
        $('authPassword').value = '';
        setAuthMode('login');
        $('authUsername').value = username;
        setMessage('Account created. Sign in with your new credentials.', 'success');
      } else {
        const result = await api('/api/auth/login', { method: 'POST', body: { username, password }, auth: false });
        if (!result || !result.access_token) throw new Error('The API did not return an access token.');
        state.token = result.access_token;
        state.username = username;
        sessionStorage.setItem('securenotes_access_token', state.token);
        sessionStorage.setItem('securenotes_username', state.username);
        $('authPassword').value = '';
        showApp();
      }
    } catch (err) {
      setMessage(err.message, 'error');
    } finally {
      submit.classList.remove('is-busy');
    }
  });

  $('newNoteButton').addEventListener('click', startNewNote);
  $('emptyNewNote').addEventListener('click', startNewNote);
  $('saveNoteButton').addEventListener('click', saveNote);
  $('deleteNoteButton').addEventListener('click', deleteNote);
  $('noteBody').addEventListener('input', () => {
    $('bodyCount').textContent = `${$('noteBody').value.length.toLocaleString()} / 2,000`;
  });
  $('noteSearch').addEventListener('input', () => {
    window.clearTimeout(state.searchTimer);
    state.searchTimer = window.setTimeout(() => loadNotes(), 300);
  });
  $('notesNav').addEventListener('click', () => showView('notes'));
  $('adminNav').addEventListener('click', () => showView('admin'));
  $('refreshAdminButton').addEventListener('click', loadAdmin);
  $('backToNotesButton').addEventListener('click', () => showView('notes'));
  $('logoutButton').addEventListener('click', () => {
    clearSession();
    setAuthMode('login');
    setMessage('You have signed out.', 'success');
    showAuth();
  });

  $('noteSearch').addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      $('noteSearch').focus();
    }
  });
  document.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k' && !$('appView').classList.contains('hidden')) {
      event.preventDefault();
      $('noteSearch').focus();
    }
    if (event.key === 'Escape' && document.activeElement === $('noteSearch')) {
      $('noteSearch').value = '';
      loadNotes();
      $('noteSearch').blur();
    }
  });

  checkHealth();
  if (state.token && state.username) {
    showApp();
  } else {
    clearSession();
    showAuth();
  }
})();
