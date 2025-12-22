/**
 * Lógica para la gestión de usuarios (Dashboard)
 */

document.addEventListener('DOMContentLoaded', () => {
    const btnUsers = document.getElementById('btnUsers');
    const modalUsers = new bootstrap.Modal(document.getElementById('modalUsers'));
    const tableBody = document.querySelector('#usersTable tbody');
    const formAddUser = document.getElementById('formAddUser');

    let isEditing = false; // Estado global para saber si es Alta o Edición

    // 1. Abrir modal y cargar usuarios
    if (btnUsers) {
        btnUsers.addEventListener('click', () => {
            loadUsers();
            resetUserForm(); // Asegurar formulario limpio al abrir
            modalUsers.show();
        });

        // Al cerrar modal, limpiar form
        document.getElementById('modalUsers').addEventListener('hidden.bs.modal', resetUserForm);
    }

    // 2. Cargar lista de usuarios
    async function loadUsers() {
        try {
            const res = await fetch('/admin/users');
            if (!res.ok) throw new Error('Error al cargar usuarios');
            const data = await res.json();
            renderUsers(data.users);
        } catch (error) {
            console.error(error);
            tableBody.innerHTML = '<tr><td colspan="4" class="text-danger">Error cargando usuarios</td></tr>';
        }
    }

    // 3. Renderizar tabla con botón EDITAR
    function renderUsers(users) {
        tableBody.innerHTML = '';
        if (!users || users.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No hay usuarios</td></tr>';
            return;
        }

        users.forEach(u => {
            // Feeds formatting
            let feeds = '';
            if (u.allowed_feeds.includes('*')) {
                feeds = '<span class="badge bg-secondary">Todo (*)</span>';
            } else {
                feeds = u.allowed_feeds.map(f => `<span class="badge bg-light text-dark border">${f}</span>`).join(' ');
            }
            if (!feeds) feeds = '<span class="text-muted small">Ninguno</span>';

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="align-middle">
                    <strong>${u.username}</strong><br>
                    ${feeds}
                </td>
                <td class="align-middle"><span class="badge bg-info text-dark">${u.role}</span></td>
                <td class="align-middle small text-muted">${u.created_at || '-'}</td>
                <td class="align-middle text-end">
                    <button class="btn btn-sm btn-outline-primary btn-edit me-1" title="Editar">
                        <i class="bi bi-pencil"></i>
                    </button>
                    ${u.username !== window.currentUser ?
                    `<button class="btn btn-sm btn-outline-danger btn-del" title="Eliminar"><i class="bi bi-trash"></i></button>` :
                    '<span class="text-muted small ms-1">(tú)</span>'}
                </td>
            `;

            // Attach event listeners safely
            const editBtn = tr.querySelector('.btn-edit');
            if (editBtn) editBtn.addEventListener('click', () => editUser(u));

            const delBtn = tr.querySelector('.btn-del');
            if (delBtn) delBtn.addEventListener('click', () => handleDelete(u.username));

            tableBody.appendChild(tr);
        });
    }

    // 4. Preparar formulario para EDITAR
    window.editUser = function (user) {
        isEditing = true;

        // Rellenar campos simples
        formAddUser.username.value = user.username;
        formAddUser.username.readOnly = true;
        formAddUser.username.classList.add('bg-light');

        formAddUser.password.value = ''; // Limpiar pass
        formAddUser.password.required = false;
        formAddUser.password.placeholder = "(Dejar en blanco para mantener)";

        formAddUser.role.value = user.role;

        // Rellenar feeds
        const allCheck = document.getElementById('feed_all');
        const checks = document.querySelectorAll('input[name="allowed_feeds"]');

        // Reset inputs
        if (allCheck) allCheck.checked = false;
        checks.forEach(c => c.checked = false);

        if (user.allowed_feeds.includes('*')) {
            if (allCheck) allCheck.checked = true;
        } else {
            user.allowed_feeds.forEach(f => {
                const cb = document.getElementById('feed_' + f);
                if (cb) cb.checked = true;
            });
        }

        // Cambiar UI del botón submit
        const btn = formAddUser.querySelector('button[type="submit"]');
        btn.textContent = "Guardar Cambios";
        btn.classList.remove('btn-primary');
        btn.classList.add('btn-warning');

        // Mostrar botón cancelar
        let cancelBtn = document.getElementById('btnCancelEdit');
        if (!cancelBtn) {
            cancelBtn = document.createElement('button');
            cancelBtn.type = "button";
            cancelBtn.id = "btnCancelEdit";
            cancelBtn.className = "btn btn-secondary w-100 mt-2";
            cancelBtn.textContent = "Cancelar Edición";
            cancelBtn.onclick = resetUserForm;
            formAddUser.appendChild(cancelBtn);
        }
    };

    // 5. Resetear formulario
    function resetUserForm() {
        isEditing = false;
        if (!formAddUser) return;

        formAddUser.reset();
        formAddUser.username.readOnly = false;
        formAddUser.username.classList.remove('bg-light');
        formAddUser.password.required = true;
        formAddUser.password.placeholder = "";

        // Feeds reset (opcional, form.reset ya lo hace, pero por seguridad)
        const checks = document.querySelectorAll('input[name="allowed_feeds"]');
        checks.forEach(c => c.checked = false);

        const btn = formAddUser.querySelector('button[type="submit"]');
        btn.textContent = "Crear Usuario";
        btn.classList.remove('btn-warning');
        btn.classList.add('btn-primary');

        const cancelBtn = document.getElementById('btnCancelEdit');
        if (cancelBtn) cancelBtn.remove();
    }

    // 6. Enviar formulario (Crear o Editar)
    if (formAddUser) {
        formAddUser.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(formAddUser);
            // Obtenemos los valores 'allow_feeds' como array manualmente si FormData no los captura bien en todos los navegadores (generalmente sí)
            const data = Object.fromEntries(formData.entries());
            data.allowed_feeds = formData.getAll('allowed_feeds');

            // URL depende del modo
            const url = isEditing ? '/admin/users/edit' : '/admin/users/add';

            try {
                const res = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await res.json();

                if (!res.ok) throw new Error(result.error || 'e: ' + result.error);
                if (result.success) {
                    resetUserForm();
                    loadUsers();

                    // Feedback visual
                    const btn = formAddUser.querySelector('button[type="submit"]');
                    const originalText = btn.textContent;
                    btn.textContent = "¡Guardado!";
                    setTimeout(() => {
                        if (!isEditing) btn.textContent = "Crear Usuario";
                    }, 1500);
                } else {
                    alert(result.error || "Error desconocido");
                }
            } catch (error) {
                console.error(error);
                alert(error.message || "Error de red");
            }
        });
    }

    // 7. Borrar usuario
    async function handleDelete(username) {
        if (!confirm(`¿Seguro que quieres borrar al usuario ${username}?`)) return;

        try {
            const res = await fetch('/admin/users/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username })
            });
            const result = await res.json();
            if (!res.ok || !result.success) throw new Error(result.error || 'Error borrando');

            loadUsers();
        } catch (error) {
            alert(error.message);
        }
    }
});
