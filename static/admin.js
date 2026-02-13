const usersBody = document.getElementById("usersBody");
const ipBansBody = document.getElementById("ipBansBody");
const logsBody = document.getElementById("logsBody");
const adminIdentity = document.getElementById("adminIdentity");

const ipBanForm = document.getElementById("ipBanForm");
const ipInput = document.getElementById("ipInput");
const ipReasonInput = document.getElementById("ipReasonInput");

const passwordForm = document.getElementById("passwordForm");
const currentPasswordInput = document.getElementById("currentPasswordInput");
const newPasswordInput = document.getElementById("newPasswordInput");

const refreshBtn = document.getElementById("refreshBtn");

const confirmModal = document.getElementById("confirmModal");
const confirmTitle = document.getElementById("confirmTitle");
const confirmMessage = document.getElementById("confirmMessage");
const confirmReasonInput = document.getElementById("confirmReasonInput");
const confirmCancelBtn = document.getElementById("confirmCancelBtn");
const confirmOkBtn = document.getElementById("confirmOkBtn");

let confirmHandler = null;

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    throw new Error(data?.error || "Ошибка запроса");
  }

  return data;
}

function showToast(message, type = "error") {
  if (!message) return;
  let container = document.querySelector(".ui-toast-container");
  if (!container) {
    container = document.createElement("div");
    container.className = "ui-toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `ui-toast ui-toast-${type}`;
  toast.textContent = String(message);
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("fade-out");
    setTimeout(() => toast.remove(), 220);
  }, 2800);
}

function openConfirmDialog({ title, message, confirmLabel = "Подтвердить", withReason = false, defaultReason = "", onConfirm }) {
  confirmTitle.textContent = title;
  confirmMessage.textContent = message;
  confirmOkBtn.textContent = confirmLabel;
  confirmReasonInput.classList.toggle("hidden", !withReason);
  confirmReasonInput.value = defaultReason;
  confirmHandler = onConfirm;
  confirmModal.classList.remove("hidden");
  confirmModal.setAttribute("aria-hidden", "false");
  if (withReason) {
    confirmReasonInput.focus();
  }
}

function closeConfirmDialog() {
  confirmModal.classList.add("hidden");
  confirmModal.setAttribute("aria-hidden", "true");
  confirmHandler = null;
  confirmReasonInput.value = "";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderUsers(users) {
  usersBody.innerHTML = "";

  if (!users.length) {
    usersBody.innerHTML = "<tr><td colspan='6'>Нет пользователей</td></tr>";
    return;
  }

  users.forEach((user) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${user.id}</td>
      <td>${escapeHtml(user.name)} (@${escapeHtml(user.username)})</td>
      <td>${escapeHtml(user.last_ip || "-")}</td>
      <td>${user.is_admin ? "admin" : "user"}</td>
      <td>${user.is_banned ? `BANNED (${escapeHtml(user.banned_reason || "без причины")})` : "active"}</td>
      <td>
        <div style="display:flex; gap:8px;">
          ${!user.is_admin && !user.is_banned ? `<button class="danger-btn ban-user" data-user-id="${user.id}" data-username="${escapeHtml(user.username)}">Бан</button>` : ""}
          ${user.is_banned ? `<button class="ghost-btn unban-user" data-user-id="${user.id}" data-username="${escapeHtml(user.username)}">Разбан</button>` : ""}
        </div>
      </td>
    `;
    usersBody.appendChild(row);
  });
}

function renderIpBans(ipBans) {
  ipBansBody.innerHTML = "";

  if (!ipBans.length) {
    ipBansBody.innerHTML = "<tr><td colspan='5'>Нет IP-банов</td></tr>";
    return;
  }

  ipBans.forEach((ban) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${ban.id}</td>
      <td>${escapeHtml(ban.ip)}</td>
      <td>${escapeHtml(ban.reason || "-")}</td>
      <td>${escapeHtml(ban.created_at)}</td>
      <td><button class="ghost-btn unban-ip" data-ban-id="${ban.id}" data-ip="${escapeHtml(ban.ip)}">Снять бан</button></td>
    `;
    ipBansBody.appendChild(row);
  });
}

function renderLogs(logs) {
  logsBody.innerHTML = "";

  if (!logs.length) {
    logsBody.innerHTML = "<tr><td colspan='5'>Лог пуст</td></tr>";
    return;
  }

  logs.forEach((log) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${escapeHtml(log.created_at)}</td>
      <td>@${escapeHtml(log.actor_username)}</td>
      <td>${escapeHtml(log.action_type)}</td>
      <td>${escapeHtml(log.target_type)}: ${escapeHtml(log.target_value)}</td>
      <td class="log-cell">${escapeHtml(log.details || "")}</td>
    `;
    logsBody.appendChild(row);
  });
}

async function loadAdminState() {
  const data = await api("/api/admin/state", { method: "GET" });
  adminIdentity.textContent = `Вы вошли как @${data.admin_username}`;
  renderUsers(data.users);
  renderIpBans(data.ip_bans);
  renderLogs(data.logs || []);
}

usersBody.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  if (target.classList.contains("ban-user")) {
    const userId = target.dataset.userId;
    const username = target.dataset.username || "user";
    openConfirmDialog({
      title: "Бан аккаунта",
      message: `Заблокировать пользователя @${username}?`,
      confirmLabel: "Забанить",
      withReason: true,
      defaultReason: "Нарушение правил",
      onConfirm: async (reason) => {
        await api(`/api/admin/users/${userId}/ban`, {
          method: "POST",
          body: JSON.stringify({ reason })
        });
        await loadAdminState();
      }
    });
  }

  if (target.classList.contains("unban-user")) {
    const userId = target.dataset.userId;
    const username = target.dataset.username || "user";
    openConfirmDialog({
      title: "Разбан аккаунта",
      message: `Разблокировать пользователя @${username}?`,
      confirmLabel: "Разбанить",
      onConfirm: async () => {
        await api(`/api/admin/users/${userId}/unban`, { method: "POST" });
        await loadAdminState();
      }
    });
  }
});

ipBansBody.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  if (target.classList.contains("unban-ip")) {
    const banId = target.dataset.banId;
    const ip = target.dataset.ip || "IP";
    openConfirmDialog({
      title: "Снятие IP-бана",
      message: `Снять блокировку с ${ip}?`,
      confirmLabel: "Снять бан",
      onConfirm: async () => {
        await api(`/api/admin/ip-bans/${banId}`, { method: "DELETE" });
        await loadAdminState();
      }
    });
  }
});

ipBanForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const ip = ipInput.value.trim();
  const reason = ipReasonInput.value.trim() || "Нарушение правил";
  if (!ip) return;

  openConfirmDialog({
    title: "IP-бан",
    message: `Заблокировать IP ${ip}?`,
    confirmLabel: "Забанить IP",
    withReason: true,
    defaultReason: reason,
    onConfirm: async (finalReason) => {
      await api("/api/admin/ip-bans", {
        method: "POST",
        body: JSON.stringify({ ip, reason: finalReason })
      });
      ipInput.value = "";
      ipReasonInput.value = "";
      await loadAdminState();
    }
  });
});

passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const currentPassword = currentPasswordInput.value;
  const newPassword = newPasswordInput.value;

  try {
    await api("/api/admin/change-password", {
      method: "POST",
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword
      })
    });
    currentPasswordInput.value = "";
    newPasswordInput.value = "";
    await loadAdminState();
    showToast("Пароль администратора изменен", "success");
  } catch (error) {
    showToast(error.message, "error");
  }
});

confirmCancelBtn.addEventListener("click", closeConfirmDialog);
confirmOkBtn.addEventListener("click", async () => {
  if (!confirmHandler) return;
  try {
    const reason = confirmReasonInput.classList.contains("hidden")
      ? ""
      : confirmReasonInput.value.trim() || "Нарушение правил";
    await confirmHandler(reason);
    closeConfirmDialog();
  } catch (error) {
    showToast(error.message, "error");
  }
});

confirmModal.addEventListener("click", (event) => {
  if (event.target === confirmModal) closeConfirmDialog();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !confirmModal.classList.contains("hidden")) {
    closeConfirmDialog();
  }
});

refreshBtn.addEventListener("click", loadAdminState);

loadAdminState().catch((error) => {
  showToast(error.message, "error");
});
