let appState = { authenticated: false, profile: null, channels: [] };
let activeChannelId = null;
let modalSaveHandler = null;
let channelSettingsSaveHandler = null;
let confirmOkHandler = null;
let callStartedAt = null;
let callTimerHandle = null;
let callMuted = false;
let callVideoEnabled = true;
let callMode = "audio";
let callRoom = null;
let localStream = null;
let socket = null;
let socketReadyPromise = null;
let selfClientId = null;
let callPingTimer = null;
const peerConnections = new Map();
const peerMeta = new Map();
let callIceServers = null;
let realtimeSocket = null;
let realtimeReconnectTimer = null;
let realtimeRefreshTimer = null;
let realtimeRefreshInFlight = false;
let realtimeRefreshPending = false;
let realtimePingTimer = null;
let realtimePollTimer = null;

const chatListEl = document.getElementById("chatList");
const feedEl = document.getElementById("feed");
const activeChatTitle = document.getElementById("activeChatTitle");
const activeChatStatus = document.getElementById("activeChatStatus");
const composer = document.getElementById("composer");
const composerInput = document.getElementById("composerInput");
const searchInput = document.getElementById("searchInput");

const subscribeBtn = document.getElementById("subscribeBtn");
const editChannelBtn = document.getElementById("editChannelBtn");
const deleteChannelBtn = document.getElementById("deleteChannelBtn");
const audioCallBtn = document.getElementById("audioCallBtn");
const videoCallBtn = document.getElementById("videoCallBtn");
const mobileChannelsBtn = document.getElementById("mobileChannelsBtn");
const mobileProfileBtn = document.getElementById("mobileProfileBtn");

const createChannelForm = document.getElementById("createChannelForm");
const channelNameInput = document.getElementById("channelNameInput");
const channelDescInput = document.getElementById("channelDescInput");
const channelCategoryInput = document.getElementById("channelCategoryInput");
const channelCoverInput = document.getElementById("channelCoverInput");
const channelPrivateInput = document.getElementById("channelPrivateInput");

const authCard = document.getElementById("authCard");
const profileCard = document.getElementById("profileCard");

const loginForm = document.getElementById("loginForm");
const loginUsername = document.getElementById("loginUsername");
const loginPassword = document.getElementById("loginPassword");

const registerForm = document.getElementById("registerForm");
const registerName = document.getElementById("registerName");
const registerUsername = document.getElementById("registerUsername");
const registerPassword = document.getElementById("registerPassword");

const logoutBtn = document.getElementById("logoutBtn");
const adminPanelBtn = document.getElementById("adminPanelBtn");
const profileChannelsBtn = document.getElementById("profileChannelsBtn");

const profileForm = document.getElementById("profileForm");
const profileNameInput = document.getElementById("profileNameInput");
const profileUsernameInput = document.getElementById("profileUsernameInput");
const profileStatusInput = document.getElementById("profileStatusInput");
const profileLocationInput = document.getElementById("profileLocationInput");
const profileWebsiteInput = document.getElementById("profileWebsiteInput");
const profileBioInput = document.getElementById("profileBioInput");
const profileAvatarInput = document.getElementById("profileAvatarInput");
const profileAvatarFile = document.getElementById("profileAvatarFile");
const avatarFileName = document.getElementById("avatarFileName");
const profileNameView = document.getElementById("profileNameView");
const profileUsernameView = document.getElementById("profileUsernameView");
const profileAvatarImage = document.getElementById("profileAvatarImage");
const profileAvatarFallback = document.getElementById("profileAvatarFallback");

const editorModal = document.getElementById("editorModal");
const editorTitle = document.getElementById("editorTitle");
const editorNameInput = document.getElementById("editorNameInput");
const editorTextInput = document.getElementById("editorTextInput");
const editorCancelBtn = document.getElementById("editorCancelBtn");
const editorSaveBtn = document.getElementById("editorSaveBtn");

const channelSettingsModal = document.getElementById("channelSettingsModal");
const channelSettingsNameInput = document.getElementById("channelSettingsNameInput");
const channelSettingsDescInput = document.getElementById("channelSettingsDescInput");
const channelSettingsCategoryInput = document.getElementById("channelSettingsCategoryInput");
const channelSettingsCoverInput = document.getElementById("channelSettingsCoverInput");
const channelSettingsPrivateInput = document.getElementById("channelSettingsPrivateInput");
const channelSettingsCancelBtn = document.getElementById("channelSettingsCancelBtn");
const channelSettingsSaveBtn = document.getElementById("channelSettingsSaveBtn");

const confirmModal = document.getElementById("confirmModal");
const confirmTitle = document.getElementById("confirmTitle");
const confirmMessage = document.getElementById("confirmMessage");
const confirmCancelBtn = document.getElementById("confirmCancelBtn");
const confirmOkBtn = document.getElementById("confirmOkBtn");

const callModal = document.getElementById("callModal");
const callTitle = document.getElementById("callTitle");
const callSubtitle = document.getElementById("callSubtitle");
const callTimer = document.getElementById("callTimer");
const callLocalVideo = document.getElementById("callLocalVideo");
const callLocalFallback = document.getElementById("callLocalFallback");
const callRemoteGrid = document.getElementById("callRemoteGrid");
const callMuteBtn = document.getElementById("callMuteBtn");
const callVideoToggleBtn = document.getElementById("callVideoToggleBtn");
const callEndBtn = document.getElementById("callEndBtn");

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
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

function initials(name) {
  return String(name)
    .split(" ")
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase() || "N";
}

function renderPostAvatar(name, avatarUrl) {
  if (avatarUrl) {
    return `<img class="chat-avatar-img" src="${escapeHtml(avatarUrl)}" alt="avatar" />`;
  }
  return `<div class="chat-avatar chat-avatar-fallback">${initials(name)}</div>`;
}

function activeChannel() {
  return appState.channels.find((channel) => channel.id === activeChannelId) || null;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });

  if (response.status === 204) return null;

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    const message = data?.error || "Ошибка запроса";
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  return data;
}

async function loadState() {
  try {
    appState = await api("/api/state", { method: "GET" });
  } catch (error) {
    if (error.status === 401) {
      appState = { authenticated: false, profile: null, channels: [] };
      activeChannelId = null;
      return;
    }
    throw error;
  }

  if (appState.channels.length === 0) {
    activeChannelId = null;
  } else if (!activeChannelId || !activeChannel()) {
    activeChannelId = appState.channels[0].id;
  }
}

function filteredChannels() {
  const q = searchInput.value.trim().toLowerCase();
  if (!q) return appState.channels;
  return appState.channels.filter((channel) => {
    return (
      channel.name.toLowerCase().includes(q) ||
      (channel.description || "").toLowerCase().includes(q) ||
      (channel.preview || "").toLowerCase().includes(q)
    );
  });
}

function openEditor({ title, name = "", text = "", showName = false, onSave }) {
  editorTitle.textContent = title;
  editorNameInput.classList.toggle("hidden", !showName);
  editorNameInput.value = name;
  editorTextInput.value = text;
  editorTextInput.placeholder = showName ? "Описание" : "Текст поста";
  modalSaveHandler = onSave;
  editorModal.classList.remove("hidden");
  editorModal.setAttribute("aria-hidden", "false");

  if (showName) {
    editorNameInput.focus();
  } else {
    editorTextInput.focus();
  }
}

function closeEditor() {
  editorModal.classList.add("hidden");
  editorModal.setAttribute("aria-hidden", "true");
  modalSaveHandler = null;
}

function openChannelSettings(channel, onSave) {
  channelSettingsNameInput.value = channel.name || "";
  channelSettingsDescInput.value = channel.description || "";
  channelSettingsCategoryInput.value = channel.category || "";
  channelSettingsCoverInput.value = channel.cover_url || "";
  channelSettingsPrivateInput.checked = Boolean(channel.is_private);
  channelSettingsSaveHandler = onSave;
  channelSettingsModal.classList.remove("hidden");
  channelSettingsModal.setAttribute("aria-hidden", "false");
  channelSettingsNameInput.focus();
}

function closeChannelSettings() {
  channelSettingsModal.classList.add("hidden");
  channelSettingsModal.setAttribute("aria-hidden", "true");
  channelSettingsSaveHandler = null;
}

function openConfirmDialog({ title, message, confirmLabel = "Удалить", onConfirm }) {
  confirmTitle.textContent = title;
  confirmMessage.textContent = message;
  confirmOkBtn.textContent = confirmLabel;
  confirmOkHandler = onConfirm;
  confirmModal.classList.remove("hidden");
  confirmModal.setAttribute("aria-hidden", "false");
}

function closeConfirmDialog() {
  confirmModal.classList.add("hidden");
  confirmModal.setAttribute("aria-hidden", "true");
  confirmOkHandler = null;
}

function formatCallDuration(seconds) {
  const mm = String(Math.floor(seconds / 60)).padStart(2, "0");
  const ss = String(seconds % 60).padStart(2, "0");
  return `${mm}:${ss}`;
}

function updateCallTimer() {
  if (callStartedAt === null) {
    callTimer.textContent = "00:00";
    return;
  }
  const elapsed = Math.max(0, Math.floor((Date.now() - callStartedAt) / 1000));
  callTimer.textContent = formatCallDuration(elapsed);
}

async function ensureSocket() {
  if (socket && socket.readyState === WebSocket.OPEN) return socket;
  if (socketReadyPromise) return socketReadyPromise;

  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const wsUrl = `${protocol}://${window.location.host}/ws/call`;
  socket = new WebSocket(wsUrl);

  socketReadyPromise = new Promise((resolve, reject) => {
    socket.onopen = () => resolve(socket);
    socket.onerror = () => reject(new Error("Ошибка подключения к звонку"));
  });

  socket.onmessage = async (event) => {
    let payload = {};
    try {
      payload = JSON.parse(event.data);
    } catch {
      return;
    }

    const evt = payload?.event;
    if (evt === "ws_ready") {
      selfClientId = payload.client_id || null;
      return;
    }
    if (evt === "call_error") {
      showToast(payload?.message || "Ошибка звонка", "error");
      return;
    }
    if (evt === "call_joined") {
      callRoom = payload.room || null;
      selfClientId = payload.self_client_id || selfClientId;
      const participants = Array.isArray(payload.participants) ? payload.participants : [];
      callSubtitle.textContent = `В звонке: ${participants.length + 1}`;
      for (const participant of participants) {
        const remoteId = participant.client_id;
        if (!remoteId || !selfClientId) continue;
        await ensurePeerConnection(remoteId, participant, selfClientId > remoteId);
      }
      return;
    }
    if (evt === "call_participant_joined") {
      const remoteId = payload.client_id;
      if (!remoteId || !selfClientId) return;
      callSubtitle.textContent = `В звонке: ${peerConnections.size + 2}`;
      await ensurePeerConnection(remoteId, payload, selfClientId > remoteId);
      return;
    }
    if (evt === "call_participant_left") {
      const remoteId = payload.client_id;
      if (!remoteId) return;
      removePeer(remoteId);
      callSubtitle.textContent = `В звонке: ${peerConnections.size + 1}`;
      return;
    }
    if (evt === "call_signal") {
      const from = payload?.from;
      const signal = payload?.signal;
      if (!from || !signal) return;

      const pc = await ensurePeerConnection(from, { client_id: from }, false);
      if (!pc) return;
      const meta = peerMeta.get(from);
      if (!meta) return;

      if (signal.description) {
        const isOffer = signal.description.type === "offer";
        const offerCollision = isOffer && (meta.makingOffer || pc.signalingState !== "stable");
        meta.ignoreOffer = !meta.polite && offerCollision;
        if (meta.ignoreOffer) return;

        await pc.setRemoteDescription(new RTCSessionDescription(signal.description));
        if (isOffer) {
          const answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);
          wsEmit("call_signal", { to: from, signal: { description: pc.localDescription } });
        }
      }
      if (signal.candidate) {
        try {
          await pc.addIceCandidate(new RTCIceCandidate(signal.candidate));
        } catch {}
      }
    }
  };

  socket.onclose = () => {
    if (callPingTimer !== null) {
      clearInterval(callPingTimer);
      callPingTimer = null;
    }
    socket = null;
    socketReadyPromise = null;
    selfClientId = null;
    if (!callModal.classList.contains("hidden")) {
      closeCallModal();
      showToast("Соединение звонка прервано", "error");
    }
  };

  try {
    await socketReadyPromise;
    if (callPingTimer !== null) {
      clearInterval(callPingTimer);
    }
    callPingTimer = setInterval(() => {
      wsEmit("ping");
    }, 25000);
    return socket;
  } catch (error) {
    socket = null;
    socketReadyPromise = null;
    showToast(error.message, "error");
    return null;
  }
}

function wsEmit(eventName, payload = {}) {
  if (!socket || socket.readyState !== WebSocket.OPEN) return;
  socket.send(JSON.stringify({ event: eventName, ...payload }));
}

function renderLocalCallPreview() {
  callLocalVideo.classList.toggle("hidden", !callVideoEnabled);
  callLocalFallback.classList.toggle("hidden", callVideoEnabled);
}

async function ensureCallConfig() {
  if (Array.isArray(callIceServers) && callIceServers.length > 0) {
    return callIceServers;
  }

  try {
    const data = await api("/api/call/config", { method: "GET" });
    if (Array.isArray(data?.ice_servers) && data.ice_servers.length > 0) {
      callIceServers = data.ice_servers;
      return callIceServers;
    }
  } catch {}

  callIceServers = [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
    { urls: "stun:stun2.l.google.com:19302" },
  ];
  return callIceServers;
}

function callParticipantName(participant) {
  if (participant?.name) return participant.name;
  if (participant?.username) return `@${participant.username}`;
  return "Участник";
}

function buildCallAvatar(name, avatarUrl) {
  const holder = document.createElement("div");
  holder.className = "call-avatar";

  if (avatarUrl) {
    const image = document.createElement("img");
    image.className = "call-avatar-img";
    image.src = avatarUrl;
    image.alt = "avatar";
    holder.appendChild(image);
    return holder;
  }

  const fallback = document.createElement("div");
  fallback.className = "call-avatar-fallback";
  fallback.textContent = initials(name);
  holder.appendChild(fallback);
  return holder;
}

function renderLocalCallFallback() {
  const displayName = appState.profile?.name || "Вы";
  const avatarUrl = appState.profile?.avatar_url || "";
  callLocalFallback.innerHTML = "";
  callLocalFallback.appendChild(buildCallAvatar(displayName, avatarUrl));

  const name = document.createElement("div");
  name.className = "call-fallback-name";
  name.textContent = displayName;
  callLocalFallback.appendChild(name);
}

function updateRemoteVideoState(sid) {
  const tile = callRemoteGrid.querySelector(`[data-remote-sid="${sid}"]`);
  if (!tile) return;
  const video = tile.querySelector("video");
  const fallback = tile.querySelector(".call-remote-fallback");
  if (!video || !fallback) return;

  const hasVideoTrack = Boolean(video.srcObject?.getVideoTracks().length);
  fallback.classList.toggle("hidden", hasVideoTrack);
}

function upsertRemoteTile(sid, participant) {
  let tile = callRemoteGrid.querySelector(`[data-remote-sid="${sid}"]`);
  const displayName = callParticipantName(participant);
  const metaLabel = participant?.username ? `@${participant.username}` : displayName;

  if (!tile) {
    tile = document.createElement("div");
    tile.className = "call-remote-tile";
    tile.dataset.remoteSid = sid;

    const media = document.createElement("div");
    media.className = "call-remote-media";

    const video = document.createElement("video");
    video.autoplay = true;
    video.playsInline = true;
    video.className = "call-remote-video";

    const fallback = document.createElement("div");
    fallback.className = "call-remote-fallback";

    const meta = document.createElement("div");
    meta.className = "call-remote-meta";

    media.appendChild(video);
    media.appendChild(fallback);
    tile.appendChild(media);
    tile.appendChild(meta);
    callRemoteGrid.appendChild(tile);
  }

  const fallback = tile.querySelector(".call-remote-fallback");
  const meta = tile.querySelector(".call-remote-meta");
  if (fallback) {
    fallback.innerHTML = "";
    fallback.appendChild(buildCallAvatar(displayName, participant?.avatar_url || ""));

    const name = document.createElement("div");
    name.className = "call-fallback-name";
    name.textContent = displayName;
    fallback.appendChild(name);
  }
  if (meta) {
    meta.textContent = metaLabel;
  }

  updateRemoteVideoState(sid);
}

function removeRemoteTile(sid) {
  const tile = callRemoteGrid.querySelector(`[data-remote-sid="${sid}"]`);
  if (!tile) return;
  const video = tile.querySelector("video");
  if (video && video.srcObject) {
    video.srcObject.getTracks().forEach((track) => track.stop());
    video.srcObject = null;
  }
  tile.remove();
}

async function ensurePeerConnection(remoteSid, participant, initiate) {
  if (!localStream || !socket || socket.readyState !== WebSocket.OPEN) return null;
  if (peerConnections.has(remoteSid)) return peerConnections.get(remoteSid);
  const iceServers = await ensureCallConfig();

  const pc = new RTCPeerConnection({
    iceServers,
  });
  peerConnections.set(remoteSid, pc);
  peerMeta.set(remoteSid, {
    makingOffer: false,
    ignoreOffer: false,
    polite: Boolean(selfClientId && selfClientId < remoteSid),
  });

  localStream.getTracks().forEach((track) => pc.addTrack(track, localStream));

  upsertRemoteTile(remoteSid, participant);

  pc.onicecandidate = (event) => {
    if (!event.candidate) return;
    wsEmit("call_signal", {
      to: remoteSid,
      signal: { candidate: event.candidate }
    });
  };

  pc.ontrack = (event) => {
    upsertRemoteTile(remoteSid, participant);
    const video = callRemoteGrid.querySelector(`[data-remote-sid="${remoteSid}"] video`);
    if (video && event.streams[0]) {
      video.srcObject = event.streams[0];
      updateRemoteVideoState(remoteSid);
    }
  };

  pc.onconnectionstatechange = () => {
    if (["failed", "disconnected", "closed"].includes(pc.connectionState)) {
      removePeer(remoteSid);
    }
  };

  if (initiate) {
    const meta = peerMeta.get(remoteSid);
    if (meta) {
      try {
        meta.makingOffer = true;
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        wsEmit("call_signal", {
          to: remoteSid,
          signal: { description: pc.localDescription }
        });
      } finally {
        meta.makingOffer = false;
      }
    }
  }

  return pc;
}

function removePeer(remoteSid) {
  const pc = peerConnections.get(remoteSid);
  if (pc) {
    pc.onicecandidate = null;
    pc.ontrack = null;
    pc.close();
    peerConnections.delete(remoteSid);
  }
  peerMeta.delete(remoteSid);
  removeRemoteTile(remoteSid);
}

async function closeCallModal() {
  if (socket && socket.readyState === WebSocket.OPEN && callRoom) {
    wsEmit("call_leave");
  }
  if (callPingTimer !== null) {
    clearInterval(callPingTimer);
    callPingTimer = null;
  }
  callRoom = null;

  for (const sid of Array.from(peerConnections.keys())) {
    removePeer(sid);
  }

  if (localStream) {
    localStream.getTracks().forEach((track) => track.stop());
    localStream = null;
  }
  callLocalVideo.srcObject = null;
  callRemoteGrid.innerHTML = "";

  callModal.classList.add("hidden");
  callModal.setAttribute("aria-hidden", "true");
  callStartedAt = null;
  if (callTimerHandle !== null) {
    clearInterval(callTimerHandle);
    callTimerHandle = null;
  }
  updateCallTimer();
}

async function openCallModal(mode) {
  const channel = activeChannel();
  if (!channel) {
    showToast("Выберите канал для звонка", "error");
    return;
  }
  if (!channel.is_subscribed) {
    showToast("Подпишитесь на канал перед звонком", "error");
    return;
  }

  const sock = await ensureSocket();
  if (!sock) return;

  callMuted = false;
  callMode = mode === "video" ? "video" : "audio";
  callVideoEnabled = callMode === "video";
  callMuteBtn.textContent = "Микрофон: вкл";
  callVideoToggleBtn.textContent = `Видео: ${callVideoEnabled ? "вкл" : "выкл"}`;
  renderLocalCallPreview();

  callTitle.textContent = callMode === "video" ? "Видеозвонок" : "Аудиозвонок";
  callSubtitle.textContent = `${channel.name} • подключение...`;
  renderLocalCallFallback();

  try {
    localStream = await navigator.mediaDevices.getUserMedia({
      audio: true,
      video: callVideoEnabled,
    });
  } catch {
    showToast("Не удалось получить доступ к микрофону/камере", "error");
    return;
  }

  callLocalVideo.srcObject = localStream;
  callRemoteGrid.innerHTML = "";
  callStartedAt = Date.now();
  updateCallTimer();
  if (callTimerHandle !== null) clearInterval(callTimerHandle);
  callTimerHandle = setInterval(updateCallTimer, 1000);

  callModal.classList.remove("hidden");
  callModal.setAttribute("aria-hidden", "false");
  wsEmit("call_join", { channel_id: channel.id, mode: callMode });
}

function toggleMobilePanel(panel) {
  const shell = document.querySelector(".app-shell");
  if (!shell) return;
  shell.classList.toggle("show-sidebar", panel === "sidebar");
  shell.classList.toggle("show-right-panel", panel === "right");
}

function renderAuth() {
  const isAuth = appState.authenticated;
  authCard.classList.toggle("hidden", isAuth);
  profileCard.classList.toggle("hidden", !isAuth);

  createChannelForm.querySelector("button").disabled = !isAuth;
  channelNameInput.disabled = !isAuth;
  channelDescInput.disabled = !isAuth;
  channelCategoryInput.disabled = !isAuth;
  channelCoverInput.disabled = !isAuth;
  channelPrivateInput.disabled = !isAuth;

  if (!isAuth) {
    closeRealtimeSocket();
    if (!callModal.classList.contains("hidden")) {
      closeCallModal();
    }
    activeChatTitle.textContent = "Каналы NSocial";
    activeChatStatus.textContent = "Войдите или зарегистрируйтесь, чтобы продолжить.";
    feedEl.innerHTML = "<article class='empty-main'>Авторизуйтесь для доступа к каналам.</article>";
    chatListEl.innerHTML = "<article class='empty'>Требуется вход</article>";
    composerInput.disabled = true;
    subscribeBtn.disabled = true;
    editChannelBtn.disabled = true;
    deleteChannelBtn.disabled = true;
    audioCallBtn.disabled = true;
    videoCallBtn.disabled = true;
    adminPanelBtn.classList.add("hidden");
  } else {
    syncRealtimeConnection();
  }
}

function renderChannels() {
  chatListEl.innerHTML = "";
  if (!appState.authenticated) return;

  const channels = filteredChannels();
  if (channels.length === 0) {
    chatListEl.innerHTML = "<article class='empty'>Нет каналов. Создайте первый канал.</article>";
    return;
  }

  channels.forEach((channel) => {
    const item = document.createElement("button");
    item.className = `chat-item${channel.id === activeChannelId ? " active" : ""}`;
    item.type = "button";
    item.innerHTML = `
      <div class="chat-avatar">${initials(channel.name)}</div>
      <div class="chat-meta">
        <h4>${escapeHtml(channel.name)}</h4>
        <p>${escapeHtml(channel.preview || channel.description || "Без постов")}</p>
      </div>
      <div class="chat-time">${escapeHtml(channel.my_role || "guest")}</div>
    `;

    item.addEventListener("click", () => {
      activeChannelId = channel.id;
      renderMain();
      renderChannels();
      toggleMobilePanel("none");
    });

    chatListEl.appendChild(item);
  });
}

function renderChannelActions(channel) {
  if (!channel) {
    subscribeBtn.disabled = true;
    editChannelBtn.disabled = true;
    deleteChannelBtn.disabled = true;
    audioCallBtn.disabled = true;
    videoCallBtn.disabled = true;
    return;
  }

  subscribeBtn.disabled = false;
  if (channel.is_subscribed) {
    subscribeBtn.textContent = channel.my_role === "admin" ? "Вы админ" : "Отписаться";
    subscribeBtn.disabled = channel.my_role === "admin";
  } else {
    subscribeBtn.textContent = "Подписаться";
  }

  editChannelBtn.disabled = !channel.can_edit_channel;
  deleteChannelBtn.disabled = !channel.can_delete_channel;
  audioCallBtn.disabled = !channel.is_subscribed;
  videoCallBtn.disabled = !channel.is_subscribed;
}

function renderMain() {
  if (!appState.authenticated) return;

  const channel = activeChannel();
  renderChannelActions(channel);

  if (!channel) {
    activeChatTitle.textContent = "Каналы NSocial";
    activeChatStatus.textContent = "Создайте канал слева, чтобы начать публикации.";
    feedEl.innerHTML = "<article class='empty-main'>Пока нет каналов и постов.</article>";
    composerInput.disabled = true;
    return;
  }

  activeChatTitle.textContent = channel.name;
  const privateMark = channel.is_private ? "приватный" : "публичный";
  const category = channel.category ? ` • ${channel.category}` : "";
  activeChatStatus.textContent = `${channel.description || "Описание канала не задано"} • ${privateMark}${category} • роль: ${channel.my_role || "guest"}`;
  composerInput.disabled = !channel.can_post;

  if (!channel.posts.length) {
    feedEl.innerHTML = "<article class='empty-main'>В этом канале еще нет постов.</article>";
    return;
  }

  feedEl.innerHTML = "";
  channel.posts.forEach((post) => {
    const card = document.createElement("article");
    card.className = "post";
    card.innerHTML = `
      <div class="post-head">
        ${renderPostAvatar(post.user, post.avatar_url)}
        <div class="post-user">
          <h5>${escapeHtml(post.user)}</h5>
          <span>${escapeHtml(post.handle)} • ${escapeHtml(post.sent_at || "")}${post.edited ? " • edited" : ""}</span>
        </div>
      </div>
      <p>${escapeHtml(post.text)}</p>
      <div class="post-actions">
        ${post.can_edit ? `<button type="button" class="ghost-btn post-edit" data-post-id="${post.id}">Редактировать</button>` : ""}
        ${post.can_delete ? `<button type="button" class="danger-btn post-delete" data-post-id="${post.id}">Удалить</button>` : ""}
      </div>
    `;
    feedEl.appendChild(card);
  });
}

function renderProfile() {
  if (!appState.authenticated || !appState.profile) return;

  const profile = appState.profile;
  adminPanelBtn.classList.toggle("hidden", !profile.is_admin);
  profileNameView.textContent = profile.name;
  profileUsernameView.textContent = `@${profile.username}`;

  profileNameInput.value = profile.name;
  profileUsernameInput.value = profile.username;
  profileStatusInput.value = profile.status_text || "";
  profileLocationInput.value = profile.location || "";
  profileWebsiteInput.value = profile.website || "";
  profileBioInput.value = profile.bio || "";
  profileAvatarInput.value = profile.avatar_url || "";

  if (profile.avatar_url) {
    profileAvatarImage.src = profile.avatar_url;
    profileAvatarImage.classList.remove("hidden");
    profileAvatarFallback.classList.add("hidden");
  } else {
    profileAvatarImage.classList.add("hidden");
    profileAvatarFallback.classList.remove("hidden");
    profileAvatarFallback.textContent = initials(profile.name);
  }
}

function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error("Ошибка чтения файла"));
    reader.readAsDataURL(file);
  });
}

async function refreshAndRender() {
  await loadState();
  render();
  syncRealtimeConnection();
}

function closeRealtimeSocket() {
  if (realtimeReconnectTimer !== null) {
    clearTimeout(realtimeReconnectTimer);
    realtimeReconnectTimer = null;
  }

  if (realtimeRefreshTimer !== null) {
    clearTimeout(realtimeRefreshTimer);
    realtimeRefreshTimer = null;
  }
  if (realtimePingTimer !== null) {
    clearInterval(realtimePingTimer);
    realtimePingTimer = null;
  }
  if (realtimePollTimer !== null) {
    clearInterval(realtimePollTimer);
    realtimePollTimer = null;
  }
  realtimeRefreshInFlight = false;
  realtimeRefreshPending = false;

  if (realtimeSocket) {
    realtimeSocket.onopen = null;
    realtimeSocket.onmessage = null;
    realtimeSocket.onclose = null;
    realtimeSocket.onerror = null;
    try {
      realtimeSocket.close();
    } catch {}
    realtimeSocket = null;
  }
}

async function runRealtimeRefresh() {
  if (realtimeRefreshInFlight) {
    realtimeRefreshPending = true;
    return;
  }

  realtimeRefreshInFlight = true;
  try {
    await loadState();
    render();
  } catch {}
  realtimeRefreshInFlight = false;

  if (realtimeRefreshPending) {
    realtimeRefreshPending = false;
    scheduleRealtimeRefresh();
  }
}

function scheduleRealtimeRefresh() {
  if (!appState.authenticated) return;
  if (realtimeRefreshTimer !== null) return;

  realtimeRefreshTimer = setTimeout(() => {
    realtimeRefreshTimer = null;
    runRealtimeRefresh();
  }, 140);
}

function ensureRealtimePolling() {
  if (!appState.authenticated) return;
  if (realtimePollTimer !== null) return;

  realtimePollTimer = setInterval(() => {
    runRealtimeRefresh();
  }, 4000);
}

function syncRealtimeConnection() {
  if (!appState.authenticated) {
    closeRealtimeSocket();
    return;
  }

  ensureRealtimePolling();

  if (
    realtimeSocket &&
    (realtimeSocket.readyState === WebSocket.OPEN || realtimeSocket.readyState === WebSocket.CONNECTING)
  ) {
    return;
  }

  if (realtimeReconnectTimer !== null) {
    clearTimeout(realtimeReconnectTimer);
    realtimeReconnectTimer = null;
  }

  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const wsUrl = `${protocol}://${window.location.host}/ws/realtime`;
  realtimeSocket = new WebSocket(wsUrl);

  realtimeSocket.onopen = () => {
    if (realtimePingTimer !== null) {
      clearInterval(realtimePingTimer);
    }
    realtimePingTimer = setInterval(() => {
      if (!realtimeSocket || realtimeSocket.readyState !== WebSocket.OPEN) return;
      realtimeSocket.send(JSON.stringify({ event: "ping" }));
    }, 25000);
  };

  realtimeSocket.onmessage = (event) => {
    let payload = {};
    try {
      payload = JSON.parse(event.data);
    } catch {
      return;
    }

    if (payload?.event === "state_changed") {
      scheduleRealtimeRefresh();
    }
  };

  realtimeSocket.onclose = () => {
    if (realtimePingTimer !== null) {
      clearInterval(realtimePingTimer);
      realtimePingTimer = null;
    }
    realtimeSocket = null;
    if (!appState.authenticated) return;
    realtimeReconnectTimer = setTimeout(() => {
      realtimeReconnectTimer = null;
      syncRealtimeConnection();
    }, 1600);
  };

  realtimeSocket.onerror = () => {};
}

createChannelForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!appState.authenticated) return;

  const name = channelNameInput.value.trim();
  const description = channelDescInput.value.trim();
  const category = channelCategoryInput.value.trim();
  const cover_url = channelCoverInput.value.trim();
  const is_private = channelPrivateInput.checked;
  if (!name) return;

  try {
    const channel = await api("/api/channels", {
      method: "POST",
      body: JSON.stringify({ name, description, category, cover_url, is_private })
    });
    channelNameInput.value = "";
    channelDescInput.value = "";
    channelCategoryInput.value = "";
    channelCoverInput.value = "";
    channelPrivateInput.checked = false;
    activeChannelId = channel.id;
    await refreshAndRender();
  } catch (error) {
    showToast(error.message, "error");
  }
});

composer.addEventListener("submit", async (event) => {
  event.preventDefault();
  const channel = activeChannel();
  if (!channel || !channel.can_post) return;

  const text = composerInput.value.trim();
  if (!text) return;

  try {
    await api(`/api/channels/${channel.id}/posts`, {
      method: "POST",
      body: JSON.stringify({ text })
    });
    composerInput.value = "";
    await refreshAndRender();
  } catch (error) {
    showToast(error.message, "error");
  }
});

subscribeBtn.addEventListener("click", async () => {
  const channel = activeChannel();
  if (!channel) return;

  try {
    if (channel.is_subscribed) {
      await api(`/api/channels/${channel.id}/unsubscribe`, { method: "POST" });
    } else {
      await api(`/api/channels/${channel.id}/subscribe`, { method: "POST" });
    }
    await refreshAndRender();
  } catch (error) {
    showToast(error.message, "error");
  }
});

editChannelBtn.addEventListener("click", () => {
  const channel = activeChannel();
  if (!channel || !channel.can_edit_channel) return;

  openChannelSettings(channel, async () => {
      const name = channelSettingsNameInput.value.trim();
      const description = channelSettingsDescInput.value.trim();
      const category = channelSettingsCategoryInput.value.trim();
      const cover_url = channelSettingsCoverInput.value.trim();
      const is_private = channelSettingsPrivateInput.checked;
      await api(`/api/channels/${channel.id}`, {
        method: "PATCH",
        body: JSON.stringify({ name, description, category, cover_url, is_private })
      });
      await refreshAndRender();
      closeChannelSettings();
    });
});

deleteChannelBtn.addEventListener("click", async () => {
  const channel = activeChannel();
  if (!channel || !channel.can_delete_channel) return;
  openConfirmDialog({
    title: "Удаление канала",
    message: `Удалить канал "${channel.name}" и все его посты?`,
    confirmLabel: "Удалить канал",
    onConfirm: async () => {
      await api(`/api/channels/${channel.id}`, { method: "DELETE" });
      activeChannelId = null;
      await refreshAndRender();
      closeConfirmDialog();
    }
  });
});

feedEl.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  const channel = activeChannel();
  if (!channel) return;

  if (target.classList.contains("post-edit")) {
    const postId = target.dataset.postId;
    const post = channel.posts.find((item) => String(item.id) === postId);
    if (!post) return;

    openEditor({
      title: "Редактировать пост",
      text: post.text,
      onSave: async () => {
        await api(`/api/channels/${channel.id}/posts/${post.id}`, {
          method: "PATCH",
          body: JSON.stringify({ text: editorTextInput.value.trim() })
        });
        await refreshAndRender();
      }
    });
  }

  if (target.classList.contains("post-delete")) {
    const postId = target.dataset.postId;
    const post = channel.posts.find((item) => String(item.id) === postId);
    if (!post) return;

    openConfirmDialog({
      title: "Удаление поста",
      message: `Удалить пост "${post.text.slice(0, 80)}${post.text.length > 80 ? "..." : ""}"?`,
      confirmLabel: "Удалить пост",
      onConfirm: async () => {
        await api(`/api/channels/${channel.id}/posts/${postId}`, {
          method: "DELETE"
        });
        await refreshAndRender();
        closeConfirmDialog();
      }
    });
  }
});

profileAvatarFile.addEventListener("change", () => {
  const file = profileAvatarFile.files?.[0];
  avatarFileName.textContent = file ? file.name : "Файл не выбран";
});

profileForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!appState.authenticated) return;

  try {
    let avatarValue = profileAvatarInput.value.trim();
    const file = profileAvatarFile.files?.[0];
    if (file) {
      avatarValue = await fileToDataUrl(file);
    }

    await api("/api/profile", {
      method: "PATCH",
      body: JSON.stringify({
        name: profileNameInput.value.trim(),
        username: profileUsernameInput.value.trim(),
        status_text: profileStatusInput.value.trim(),
        location: profileLocationInput.value.trim(),
        website: profileWebsiteInput.value.trim(),
        bio: profileBioInput.value.trim(),
        avatar_url: avatarValue
      })
    });

    profileAvatarFile.value = "";
    avatarFileName.textContent = "Файл не выбран";
    await refreshAndRender();
  } catch (error) {
    showToast(error.message, "error");
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: loginUsername.value.trim(),
        password: loginPassword.value
      })
    });
    loginPassword.value = "";
    await refreshAndRender();
  } catch (error) {
    showToast(error.message, "error");
  }
});

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        name: registerName.value.trim(),
        username: registerUsername.value.trim(),
        password: registerPassword.value
      })
    });

    registerPassword.value = "";
    await refreshAndRender();
  } catch (error) {
    showToast(error.message, "error");
  }
});

logoutBtn.addEventListener("click", async () => {
  try {
    if (!callModal.classList.contains("hidden")) {
      await closeCallModal();
    }
    await api("/api/auth/logout", { method: "POST" });
    await refreshAndRender();
  } catch (error) {
    showToast(error.message, "error");
  }
});

adminPanelBtn.addEventListener("click", () => {
  window.location.href = "/admin";
});

audioCallBtn.addEventListener("click", async () => openCallModal("audio"));
videoCallBtn.addEventListener("click", async () => openCallModal("video"));

callMuteBtn.addEventListener("click", () => {
  callMuted = !callMuted;
  if (localStream) {
    localStream.getAudioTracks().forEach((track) => {
      track.enabled = !callMuted;
    });
  }
  callMuteBtn.textContent = `Микрофон: ${callMuted ? "выкл" : "вкл"}`;
});

callVideoToggleBtn.addEventListener("click", async () => {
  callVideoEnabled = !callVideoEnabled;
  if (localStream) {
    if (callVideoEnabled && localStream.getVideoTracks().length === 0) {
      try {
        const media = await navigator.mediaDevices.getUserMedia({ video: true });
        const [track] = media.getVideoTracks();
        if (track) {
          localStream.addTrack(track);
          for (const pc of peerConnections.values()) {
            pc.addTrack(track, localStream);
          }
        }
      } catch {
        showToast("Не удалось включить камеру", "error");
        callVideoEnabled = false;
      }
    } else {
      localStream.getVideoTracks().forEach((track) => {
        track.enabled = callVideoEnabled;
      });
    }
  }
  renderLocalCallPreview();
  callVideoToggleBtn.textContent = `Видео: ${callVideoEnabled ? "вкл" : "выкл"}`;
});

callEndBtn.addEventListener("click", async () => {
  await closeCallModal();
  showToast("Звонок завершен", "success");
});

mobileChannelsBtn.addEventListener("click", () => toggleMobilePanel("sidebar"));
mobileProfileBtn.addEventListener("click", () => toggleMobilePanel("right"));
profileChannelsBtn.addEventListener("click", () => toggleMobilePanel("sidebar"));

channelSettingsCancelBtn.addEventListener("click", closeChannelSettings);
channelSettingsSaveBtn.addEventListener("click", async () => {
  if (!channelSettingsSaveHandler) return;
  try {
    await channelSettingsSaveHandler();
  } catch (error) {
    showToast(error.message, "error");
  }
});

confirmCancelBtn.addEventListener("click", closeConfirmDialog);
confirmOkBtn.addEventListener("click", async () => {
  if (!confirmOkHandler) return;
  try {
    await confirmOkHandler();
  } catch (error) {
    showToast(error.message, "error");
  }
});

editorCancelBtn.addEventListener("click", closeEditor);

editorSaveBtn.addEventListener("click", async () => {
  if (!modalSaveHandler) return;
  try {
    await modalSaveHandler();
    closeEditor();
  } catch (error) {
    showToast(error.message, "error");
  }
});

editorModal.addEventListener("click", (event) => {
  if (event.target === editorModal) {
    closeEditor();
  }
});

channelSettingsModal.addEventListener("click", (event) => {
  if (event.target === channelSettingsModal) {
    closeChannelSettings();
  }
});

confirmModal.addEventListener("click", (event) => {
  if (event.target === confirmModal) {
    closeConfirmDialog();
  }
});

callModal.addEventListener("click", (event) => {
  if (event.target === callModal) {
    closeCallModal();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;

  if (!editorModal.classList.contains("hidden")) {
    closeEditor();
  }
  if (!channelSettingsModal.classList.contains("hidden")) {
    closeChannelSettings();
  }
  if (!confirmModal.classList.contains("hidden")) {
    closeConfirmDialog();
  }
  if (!callModal.classList.contains("hidden")) {
    closeCallModal();
  }
  toggleMobilePanel("none");
});

window.addEventListener("beforeunload", () => {
  if (socket && socket.readyState === WebSocket.OPEN && callRoom) {
    wsEmit("call_leave");
  }
  closeRealtimeSocket();
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && appState.authenticated) {
    scheduleRealtimeRefresh();
    syncRealtimeConnection();
  }
});

searchInput.addEventListener("input", renderChannels);

function render() {
  renderAuth();
  renderChannels();
  renderMain();
  renderProfile();
}

async function init() {
  try {
    await loadState();
    render();
    syncRealtimeConnection();
  } catch (error) {
    activeChatStatus.textContent = error.message;
  }
}

init();
