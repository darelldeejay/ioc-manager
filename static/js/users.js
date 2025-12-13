/**
 * Lógica para la gestión de usuarios (Dashboard)
 */

document.addEventListener('DOMContentLoaded', () => {
    const btnUsers = document.getElementById('btnUsers');
    const modalUsers = new bootstrap.Modal(document.getElementById('modalUsers'));
    const tableBody = document.querySelector('#usersTable tbody');
    const formAddUser = document.getElementById('formAddUser');
    const formChangePass = document.getElementById('formChangePass');

    // 1. Abrir modal y cargar usuarios
    if (btnUsers) {
        btnUsers.addEventListener('click', () => {
            loadUsers();
            modalUsers.show();
        });
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

    // 3. Renderizar tabla
    function renderUsers(users) {
        tableBody.innerHTML = '';
        users.forEach(u => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${u.username}</td>
                <td><span class="badge bg-secondary">${u.role}</span></td>
                <td>${u.created_at || '-'}</td>
                <td>
                    <button class="btn btn-sm btn-outline-warning btn-pass" data-user="${u.username}">🔑 Clave</button>
                    ${u.username !== window.currentUser ?
                    `<button class="btn btn-sm btn-outline-danger btn-del" data-user="${u.username}">🗑️</button>` :
                    '<span class="text-muted small">(tú)</span>'}
                </td>
            `;
            tableBody.appendChild(tr);
        });

        // Eventos de botones en fila
        document.querySelectorAll('.btn-del').forEach(b => {
            b.addEventListener('click', (e) => handleDelete(e.target.dataset.user));
        });
        document.querySelectorAll('.btn-pass').forEach(b => {
            b.addEventListener('click', (e) => openPassModal(e.target.dataset.user));
        });
    }

    // 4. Crear usuario
    if (formAddUser) {
        formAddUser.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(formAddUser);
            const data = Object.fromEntries(formData.entries());

            try {
                const res = await fetch('/admin/users/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await res.json();
                if (!res.ok) throw new Error(result.error || 'Error creando usuario');

                formAddUser.reset();
                loadUsers(); // Recargar tabla
                alert('Usuario creado correctamente');
            } catch (error) {
                alert(error.message);
            }
        });
    }

    // 5. Borrar usuario
    async function handleDelete(username) {
        if (!confirm(`¿Seguro que quieres borrar al usuario ${username}?`)) return;

        try {
            const res = await fetch('/admin/users/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username })
            });
            const result = await res.json();
            if (!res.ok) throw new Error(result.error || 'Error borrando');
            loadUsers();
        } catch (error) {
            alert(error.message);
        }
    }

    // 6. Cambiar contraseña (UI simple usando prompt por ahora o sub-modal)
    // Para simplificar, reutilizaremos el formChangePass si existe, o un prompt básico mejorado.
    // Vamos a usar un prompt de JS por simplicidad extrema en esta iteración, 
    // o mejor, mostrar el formChangePass oculto.

    function openPassModal(username) {
        const newPass = prompt(`Nueva contraseña para ${username}:`);
        if (newPass) {
            changePassword(username, newPass);
        }
    }

    async function changePassword(username, password) {
        try {
            const res = await fetch('/admin/users/password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const result = await res.json();
            if (!res.ok) throw new Error(result.error || 'Error cambiando clave');
            alert('Contraseña actualizada');
        } catch (error) {
            alert(error.message);
        }
    }
});
