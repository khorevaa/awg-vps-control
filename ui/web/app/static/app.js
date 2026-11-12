"use strict";

(() => {
  const el = (id) => document.getElementById(id);
  const state = { authenticated: false, csrf: "", view: "overview", peers: [], peerPage: 1, candidates: [], policy: null, policyDirty: false, policyLoadID: 0, operations: [], selectedOperation: "", pendingRequest: null, submitting: false, loading: false, polling: false };
  const views = {
    overview: ["Обзор", "Состояние сервера", "Установка AWG, маршрут трафика и состояние VPS."],
    discovery: ["Подключение сервера", "Подключение установки", "Выбор существующего контейнера AmneziaWG и его сети."],
    peers: ["Клиенты AWG", "Клиенты AWG", "Родные данные Amnezia и наблюдаемое состояние подключений."],
    warp: ["WARP и маршруты", "Выход в интернет", "Политика WARP, проверка маршрутов и восстановление."],
    configuration: ["Конфигурация", "Конфигурация AWG", "Текущая конфигурация с маскированными секретами."],
    operations: ["Операции", "Операции и восстановление", "Принятые действия, ход выполнения и проверенный результат."],
    logs: ["Журналы", "Журналы сервера", "Ограниченные снимки журналов выбранного компонента."]
  };
  const actionNames = { attach: "Подключение установки", "policy.set": "Изменение политики", repair: "Восстановление маршрутов", "warp.setup": "Настройка WARP", "warp.reconnect": "Переподключение WARP", "awg.restart": "Ручной перезапуск AWG" };
  const operationStatuses = { queued: ["В очереди", "neutral"], running: ["Выполняется", "running"], verifying: ["Проверка результата", "running"], succeeded: ["Выполнена", "ok"], rolling_back: ["Восстановление", "warning"], rolled_back: ["Отменена с откатом", "warning"], failed: ["Ошибка", "error"], manual_recovery_required: ["Требуется восстановление", "error"] };
  const terminalStatuses = new Set(["succeeded", "rolled_back", "failed", "manual_recovery_required"]);
  const value = (input, fallback = "—") => input === null || input === undefined || input === "" ? fallback : String(input);
  const text = (id, input) => { el(id).textContent = value(input); };

  function applyTheme(theme) {
    const dark = theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    el("theme-toggle").title = dark ? "Включить светлую тему" : "Включить тёмную тему";
    el("theme-toggle").setAttribute("aria-label", el("theme-toggle").title);
  }
  let theme = "system";
  try { theme = localStorage.getItem("awg_control_theme") || "system"; } catch (_) { /* Тема остаётся в памяти. */ }
  applyTheme(theme);
  el("theme-toggle").addEventListener("click", () => {
    theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(theme);
    try { localStorage.setItem("awg_control_theme", theme); } catch (_) { /* Сохранение темы необязательно. */ }
  });
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { if (theme === "system") applyTheme(theme); });

  function dateTime(input) {
    if (!input) return "Нет проверки";
    const date = new Date(typeof input === "number" ? input * 1000 : input);
    return Number.isNaN(date.getTime()) ? "Время неизвестно" : date.toLocaleString("ru-RU");
  }
  function bytes(input) {
    if (typeof input !== "number" || !Number.isFinite(input) || input < 0) return "—";
    const units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
    let index = 0;
    while (input >= 1024 && index < units.length - 1) { input /= 1024; index++; }
    return `${input.toLocaleString("ru-RU", { maximumFractionDigits: index ? 1 : 0 })} ${units[index]}`;
  }
  function uptime(seconds) {
    if (typeof seconds !== "number" || seconds < 0) return "—";
    const days = Math.floor(seconds / 86400), hours = Math.floor(seconds % 86400 / 3600), minutes = Math.floor(seconds % 3600 / 60);
    return `${days ? `${days} д. ` : ""}${hours} ч. ${minutes} мин.`;
  }
  function setPill(element, label, kind = "neutral") { element.className = `pill ${kind}`; element.textContent = label; }
  function toast(message, error = false) {
    const node = document.createElement("div"); node.className = `toast${error ? " error" : ""}`; node.textContent = message;
    el("toasts").append(node); setTimeout(() => node.remove(), 6500);
  }
  function showError(error) {
    el("global-error").textContent = error.message || "Не удалось получить данные. Состояние сервера неизвестно.";
    el("global-error").hidden = false;
  }
  function signedOut(message = "") {
    state.authenticated = false; state.csrf = ""; state.peers = []; state.candidates = []; state.operations = []; state.policy = null; state.policyDirty = false; state.pendingRequest = null; state.selectedOperation = "";
    state.policyLoadID++; el("setup-warp").disabled = true;
    el("application").hidden = true; el("login-screen").hidden = false; el("login-error").textContent = message;
    el("peers-body").replaceChildren(); el("operations-body").replaceChildren(); text("configuration-content", "Сессия завершена."); text("logs-content", "Сессия завершена.");
    el("operation-uncertain").hidden = true; el("operation-details-card").hidden = true;
  }
  async function api(path, options = {}) {
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 40000);
    const method = options.method || "GET", headers = { Accept: "application/json" };
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET" && state.csrf) headers["X-CSRF-Token"] = state.csrf;
    try {
      const response = await fetch(`/api/v1${path}`, { method, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body), credentials: "same-origin", cache: "no-store", signal: controller.signal, redirect: "error" });
      let body;
      try { body = await response.json(); } catch (_) { throw new Error("Панель вернула некорректный ответ."); }
      if (!response.ok) {
        const error = new Error(body.error && body.error.message || `Запрос не выполнен (${response.status}).`);
        error.status = response.status; error.code = body.error && body.error.code;
        if (response.status === 401 && path !== "/access") signedOut("Сессия завершена. Войдите заново.");
        throw error;
      }
      return body;
    } catch (error) {
      if (error.name === "AbortError") throw new Error("Время ожидания истекло. Если действие уже принято, проверьте его в разделе «Операции».");
      if (error instanceof TypeError) throw new Error("Нет связи с панелью. Проверьте SSH-туннель; исход операции пока неизвестен.");
      throw error;
    } finally { clearTimeout(timeout); }
  }
  function signedIn(session) {
    state.csrf = session.csrf_token; state.authenticated = true;
    text("session-expiry", `Сессия до ${dateTime(session.expires_at)}`);
    el("login-screen").hidden = true; el("application").hidden = false; el("login-error").textContent = "";
    changeView();
  }
  el("login-form").addEventListener("submit", async (event) => {
    event.preventDefault(); el("login-submit").disabled = true; el("login-error").textContent = "";
    try { signedIn(await api("/access", { method: "POST", body: { secret: el("access-secret").value } })); }
    catch (error) { el("login-error").textContent = error.message; }
    finally { el("access-secret").value = ""; el("login-submit").disabled = false; }
  });
  el("logout").addEventListener("click", async () => {
    try { await api("/auth/logout", { method: "POST" }); signedOut(); }
    catch (error) { showError(error); }
  });

  function renderChecks(target, checks) {
    const node = el(target); node.replaceChildren();
    if (!Array.isArray(checks) || !checks.length) { const empty = document.createElement("p"); empty.className = "empty"; empty.textContent = "Нет результатов проверок."; node.append(empty); return; }
    const names = { "awg.container": "Контейнер AmneziaWG", "awg.interface": "Интерфейс AmneziaWG", "warp.service": "Служба WARP", "warp.tunnel": "Туннель WARP", "routing.capability": "Совместимость маршрутизации", "routing.managed": "Управляемые маршруты", "routing.guard": "Защита выхода", "egress.https": "Проверка HTTPS", "egress.dns": "Проверка DNS" };
    for (const check of checks) {
      const row = document.createElement("div"), pill = document.createElement("span"), copy = document.createElement("div"), heading = document.createElement("strong"), message = document.createElement("p"), when = document.createElement("small");
      row.className = "check"; copy.className = "check-copy";
      const labels = { ok: "OK", warning: "Внимание", error: "Ошибка", unknown: "Нет данных" };
      setPill(pill, labels[check.status] || "Нет данных", ["ok", "warning", "error"].includes(check.status) ? check.status : "neutral");
      heading.textContent = names[check.id] || (typeof check.id === "string" && check.id.startsWith("dependency.") ? `Зависимость: ${check.id.slice("dependency.".length)}` : value(check.id, "Проверка")); message.textContent = value(check.message, "Результат не получен"); when.textContent = dateTime(check.checked_at);
      copy.append(heading, message, when); row.append(pill, copy); node.append(row);
    }
  }
  function componentStatus(component, kind) {
    if (!component || typeof component !== "object") return "Неизвестно";
    if (kind === "awg" && typeof component.running === "boolean") return component.running ? "Работает" : "Работа не подтверждена";
    if (kind === "warp") {
      if (component.installed === false) return "Не установлен";
      if (component.installed === true && typeof component.connected === "boolean") return component.connected ? "Подключён" : "Отключён";
    }
    return "Неизвестно";
  }
  async function loadOverview() {
    const data = await api("/overview");
    text("server-hostname", data.hostname || "Сервер не определён");
    setPill(el("attachment-status"), data.attached ? "Установка подключена" : "Не подключена", data.attached ? "ok" : "warning");
    const old = !data.observed_at || Date.now() - new Date(data.observed_at).getTime() > 90000;
    text("observed-at", `${old ? "Снимок требует обновления · " : "Снимок · "}${dateTime(data.observed_at)}`); el("observed-at").classList.toggle("stale", old);
    const egress = data.egress || {}, policy = data.policy || {};
    text("egress-path", { warp: "Через WARP", direct: "Прямой выход", blocked: "Выход заблокирован", unknown: "Не проверен" }[egress.path] || "Не проверен");
    text("egress-message", egress.message || "Проверка фактического пути не выполнена"); text("egress-verified", `Проверено: ${dateTime(egress.verified_at)}`);
    text("awg-status", componentStatus(data.awg, "awg")); text("warp-status", componentStatus(data.warp, "warp"));
    const installation = data.installation || {};
    text("awg-installation", data.attached ? `${value(installation.container_name)} · ${value(installation.interface)}` : "Выберите установку в разделе подключения");
    el("restart-awg").disabled = !data.attached || installation.supported !== true;
    text("warp-policy-summary", policy.configured !== true ? "Выберите режим выхода" : policy.warp_enabled ? (policy.allow_direct_without_warp ? "WARP с разрешённым fallback" : "WARP без прямого fallback") : "WARP явно не используется");
    text("vps-uptime", uptime(data.uptime_seconds)); text("vps-load", Array.isArray(data.load_average) ? data.load_average.map((n) => Number(n).toFixed(2)).join(" / ") : "—");
    text("vps-memory", `${bytes(data.memory && data.memory.available_bytes)} / ${bytes(data.memory && data.memory.total_bytes)}`);
    text("vps-disk", `${bytes(data.disk && data.disk.free_bytes)} / ${bytes(data.disk && data.disk.total_bytes)}`);
    renderChecks("overview-checks", data.checks);
  }
  async function loadDiagnostics() {
    const data = await api("/diagnostics"); renderChecks("overview-checks", data.checks); renderChecks("warp-checks", data.checks);
    toast(`Проверки обновлены: ${dateTime(data.observed_at)}`);
  }
  function addOption(select, textValue, optionValue, disabled = false) { const option = document.createElement("option"); option.textContent = textValue; option.value = optionValue; option.disabled = disabled; select.append(option); }
  async function loadDiscovery() {
    const data = await api("/discovery"); state.candidates = Array.isArray(data.candidates) ? data.candidates : [];
    renderChecks("discovery-dependencies", data.dependencies); const select = el("candidate"); select.replaceChildren();
    addOption(select, state.candidates.length ? "Выберите существующий контейнер" : "Поддерживаемые установки не найдены", "");
    state.candidates.forEach((candidate, index) => addOption(select, `${value(candidate.container_name)}${candidate.supported !== true ? " · только диагностика" : ""}`, String(index)));
    candidateChanged();
  }
  function candidateChanged() {
    const candidate = state.candidates[Number(el("candidate").value)], hasSelection = el("candidate").value !== "";
    const network = el("docker-network"); network.replaceChildren(); addOption(network, "Выберите обнаруженную сеть", "");
    const supported = hasSelection && candidate && candidate.supported === true;
    text("candidate-reason", hasSelection && candidate ? candidate.reason || `${value(candidate.interface)} · ${value(candidate.config_path)}` : "Контейнер и сеть выбираются явно.");
    if (hasSelection && candidate) { for (const item of candidate.networks || []) { const name = typeof item === "string" ? item : item.name; if (name) addOption(network, name, name); } }
    el("dns-container").value = hasSelection && candidate ? candidate.dns_container_name || "" : "";
    el("attach-submit").disabled = !supported; network.disabled = !supported;
  }
  el("candidate").addEventListener("change", candidateChanged);
  el("attach-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const candidate = state.candidates[Number(el("candidate").value)];
    if (!candidate || !el("docker-network").value) return;
    await confirmedOperation("attach", { container_name: candidate.container_name, dns_container_name: el("dns-container").value.trim(), docker_network: el("docker-network").value }, "Подключить установку", `Подключить ${candidate.container_name} к панели через сеть ${el("docker-network").value}? AWG не будет установлен или пересоздан.`);
  });
  async function loadPeers() { const data = await api("/peers"); if (!Array.isArray(data)) throw new Error("Получен некорректный список клиентов."); state.peers = data; renderPeers(); }
  function renderPeers() {
    const query = el("peer-search").value.toLocaleLowerCase("ru"), rows = state.peers.filter((peer) => [peer.name, peer.public_key, ...(peer.allowed_ips || [])].join(" ").toLocaleLowerCase("ru").includes(query));
    const pages = Math.max(1, Math.ceil(rows.length / 20)); state.peerPage = Math.max(1, Math.min(state.peerPage, pages));
    const body = el("peers-body"); body.replaceChildren();
    for (const peer of rows.slice((state.peerPage - 1) * 20, state.peerPage * 20)) {
      const row = document.createElement("tr"), identity = document.createElement("td"), name = document.createElement("span"), key = document.createElement("span");
      name.className = "primary-cell"; name.textContent = value(peer.name, "Без имени"); key.className = "secondary mono"; key.textContent = value(peer.public_key); identity.append(name, key); row.append(identity);
      for (const cellText of [(peer.allowed_ips || []).join(", ") || "—", value(peer.endpoint), peer.latest_handshake ? dateTime(peer.latest_handshake) : "Не наблюдался", `${bytes(peer.rx_bytes)} / ${bytes(peer.tx_bytes)}`]) { const td = document.createElement("td"); td.textContent = cellText; row.append(td); }
      body.append(row);
    }
    text("peers-count", state.peers.length); text("peers-page", `${state.peerPage} / ${pages}`); el("peers-empty").hidden = rows.length > 0;
    el("peers-prev").disabled = state.peerPage <= 1; el("peers-next").disabled = state.peerPage >= pages;
  }
  el("peer-search").addEventListener("input", () => { state.peerPage = 1; renderPeers(); });
  el("peers-prev").addEventListener("click", () => { state.peerPage--; renderPeers(); });
  el("peers-next").addEventListener("click", () => { state.peerPage++; renderPeers(); });
  async function loadConfiguration() { const data = await api("/configuration"); text("configuration-name", data.filename || "Конфигурация AWG"); text("configuration-revision", `Ревизия: ${value(data.revision)}`); text("configuration-content", data.content || "Нет доступной конфигурации."); }
  async function loadPolicy() {
    const loadID = ++state.policyLoadID;
    el("setup-warp").disabled = true; el("warp-setup-guidance").hidden = false;
    text("warp-setup-guidance", "Проверяем сохранённую политику перед установкой WARP.");
    try {
      const data = await api("/policy");
      if (loadID !== state.policyLoadID) return;
      if (typeof data.revision !== "string" || typeof data.warp_enabled !== "boolean" || typeof data.allow_direct_without_warp !== "boolean") throw new Error("Не удалось прочитать политику выхода. Изменение недоступно.");
      if (!state.policyDirty) { state.policy = data; el("warp-enabled").checked = data.warp_enabled; el("allow-direct").checked = data.allow_direct_without_warp; }
      el("policy-unconfigured").hidden = data.configured === true; text("policy-revision", `Ревизия: ${value(state.policy && state.policy.revision)}`); el("policy-submit").disabled = !state.policy;
      el("setup-warp").disabled = data.configured !== true; el("warp-setup-guidance").hidden = data.configured === true;
      text("warp-setup-guidance", "Для первой установки сначала сохраните режим без WARP: оставьте «Использовать WARP» выключенным. Затем установите WARP и включите его в политике.");
    } catch (error) {
      if (loadID !== state.policyLoadID) return;
      el("setup-warp").disabled = true;
      text("warp-setup-guidance", "Не удалось проверить сохранённую политику. Обновите данные перед установкой WARP.");
      throw error;
    }
  }
  el("warp-enabled").addEventListener("change", () => { state.policyDirty = true; });
  el("allow-direct").addEventListener("change", () => { state.policyDirty = true; });
  el("policy-form").addEventListener("submit", async (event) => {
    event.preventDefault(); if (!state.policy) return;
    const warp = el("warp-enabled").checked, direct = el("allow-direct").checked;
    const message = !warp ? "Явно отключить использование WARP и выбрать прямой выход? Изменение может оборвать текущие соединения." : direct ? "Разрешить всему клиентскому трафику и DNS прямой выход при отказе WARP? После восстановления весь трафик автоматически вернётся в WARP; соединения могут оборваться." : "Использовать WARP без прямого fallback? При его отказе клиентский выход будет заблокирован. Уже действующий прямой выход прекратится, соединения могут оборваться.";
    await confirmedOperation("policy.set", { warp_enabled: warp, allow_direct_without_warp: direct, expected_revision: state.policy.revision }, "Изменить политику выхода", message);
  });
  async function loadLogs() { const data = await api(`/logs?source=${encodeURIComponent(el("log-source").value)}&limit=${el("log-limit").value}`); text("logs-metadata", `${value(data.source)} · ${dateTime(data.observed_at)}${data.truncated ? " · показана ограниченная часть журнала" : ""}`); text("logs-content", Array.isArray(data.lines) && data.lines.length ? data.lines.join("\n") : "В выбранном источнике нет строк."); }

  function confirmAction(title, message, danger = false) {
    const dialog = el("confirmation"); if (dialog.open) return Promise.resolve(false);
    text("confirmation-title", title); text("confirmation-message", message); el("confirmation-submit").className = `button ${danger ? "danger-button" : "primary"}`;
    dialog.returnValue = "cancel"; dialog.showModal();
    return new Promise((resolve) => dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true }));
  }
  function idempotencyKey() { return Array.from(crypto.getRandomValues(new Uint8Array(24)), (n) => n.toString(16).padStart(2, "0")).join(""); }
  async function confirmedOperation(action, payload, title, message, danger = false) {
    if (state.submitting) return;
    if (state.pendingRequest) { toast("Сначала уточните исход предыдущего запроса в разделе «Операции».", true); location.hash = "operations"; return; }
    if (!await confirmAction(title, message, danger)) return;
    state.pendingRequest = { action, payload, idempotency_key: idempotencyKey() };
    await sendOperation();
  }
  async function sendOperation() {
    if (state.submitting || !state.pendingRequest) return;
    state.submitting = true; el("retry-operation").disabled = true;
    try {
      const operation = await api("/operations", { method: "POST", body: state.pendingRequest });
      state.pendingRequest = null; el("operation-uncertain").hidden = true; state.selectedOperation = operation.id;
      toast("Операция принята. Ожидаем проверку результата."); location.hash = "operations"; await loadOperations(); await loadOperationDetails(operation.id);
    } catch (error) {
      showError(error);
      // После подтверждённого POST ошибка чтения истории не делает исход отправки неизвестным.
      if (!state.pendingRequest) return;
      if (error.status && error.status >= 400 && error.status < 500 && error.status !== 408) { state.pendingRequest = null; el("operation-uncertain").hidden = true; }
      else { text("operation-uncertain-message", "Ответ на запрос не подтверждён. Проверьте историю или повторите запрос с тем же ключом: повтор не должен создать второе действие."); el("operation-uncertain").hidden = false; location.hash = "operations"; }
      if (error.status === 409) { state.policyDirty = false; state.policy = null; el("policy-submit").disabled = true; }
    } finally { state.submitting = false; el("retry-operation").disabled = false; }
  }
  el("retry-operation").addEventListener("click", sendOperation);
  async function loadOperations() {
    const data = await api("/operations"); if (!Array.isArray(data)) throw new Error("Получен некорректный журнал операций.");
    const previous = new Map(state.operations.map((operation) => [operation.id, operation.status])); state.operations = data;
    const body = el("operations-body"); body.replaceChildren();
    for (const operation of data) {
      const row = document.createElement("tr"), name = document.createElement("td"), status = document.createElement("td"), badge = document.createElement("span"), created = document.createElement("td"), updated = document.createElement("td"), action = document.createElement("td"), button = document.createElement("button");
      name.textContent = actionNames[operation.action] || value(operation.action); const labels = operationStatuses[operation.status] || ["Неизвестно", "neutral"]; setPill(badge, ...labels); status.append(badge); created.textContent = dateTime(operation.created_at); updated.textContent = dateTime(operation.updated_at);
      button.className = "text-button"; button.textContent = "Подробнее"; button.addEventListener("click", () => runWithError(() => loadOperationDetails(operation.id))); action.append(button); row.append(name, status, created, updated, action); body.append(row);
      if (previous.has(operation.id) && previous.get(operation.id) !== operation.status && terminalStatuses.has(operation.status)) {
        toast(`${actionNames[operation.action] || operation.action}: ${labels[0].toLocaleLowerCase("ru")}`, operation.status !== "succeeded");
        if (operation.action === "policy.set") { state.policyDirty = false; state.policy = null; }
      }
    }
    el("operations-empty").hidden = data.length > 0; text("operations-updated", `Обновлено ${new Date().toLocaleTimeString("ru-RU")}`);
  }
  async function loadOperationDetails(id) {
    if (!id) return; state.selectedOperation = id;
    const operation = await api(`/operations/${encodeURIComponent(id)}`); el("operation-details-card").hidden = false;
    setPill(el("operation-status"), ...(operationStatuses[operation.status] || ["Неизвестно", "neutral"])); text("operation-identity", `${value(operation.id)} · ${dateTime(operation.updated_at)}`);
    if (operation.error) text("operation-result", `${value(operation.error.message, "Операция завершилась с ошибкой.")}\nКод: ${value(operation.error.code)}${operation.status === "manual_recovery_required" ? "\nТребуется проверка по SSH. Повторный перезапуск AWG автоматически не выполняется." : ""}`);
    else text("operation-result", operation.result === null || operation.result === undefined ? "Итоговый результат ещё не получен." : JSON.stringify(operation.result, null, 2));
  }
  const tasks = { overview: loadOverview, discovery: loadDiscovery, peers: loadPeers, warp: loadPolicy, configuration: loadConfiguration, operations: loadOperations, logs: loadLogs };
  async function runWithError(task) { try { await task(); } catch (error) { showError(error); } }
  async function loadView() {
    if (!state.authenticated) return;
    el("global-error").hidden = true; el("loading").hidden = false;
    try { await tasks[state.view](); }
    catch (error) { showError(error); }
    finally { el("loading").hidden = true; }
  }
  function changeView() {
    const key = location.hash.slice(1); state.view = views[key] ? key : "overview";
    const [title, heading, description] = views[state.view]; text("page-title", title); text("section-title", heading); text("section-description", description);
    document.querySelectorAll("[data-view]").forEach((node) => { node.classList.toggle("active", node.dataset.view === state.view); if (node.dataset.view === state.view) node.setAttribute("aria-current", "page"); else node.removeAttribute("aria-current"); });
    document.querySelectorAll("[data-panel]").forEach((node) => { node.hidden = node.dataset.panel !== state.view; });
    loadView();
  }
  window.addEventListener("hashchange", changeView);
  el("refresh").addEventListener("click", loadView);
  el("discover").addEventListener("click", () => runWithError(loadDiscovery));
  el("run-diagnostics").addEventListener("click", () => runWithError(loadDiagnostics));
  el("warp-diagnostics").addEventListener("click", () => runWithError(loadDiagnostics));
  el("load-logs").addEventListener("click", () => runWithError(loadLogs));
  el("restart-awg").addEventListener("click", () => confirmedOperation("awg.restart", {}, "Перезапустить AWG", "Перезапустить существующий контейнер AWG? Активные VPN-соединения прервутся. Это ручное действие; восстановление WARP само AWG не перезапускает.", true));
  el("setup-warp").addEventListener("click", () => confirmedOperation("warp.setup", {}, "Установить / настроить WARP", "Выполнить отдельную установку или настройку WARP и его интеграции? Операция может занять несколько минут и затронуть маршруты. AWG не будет установлен или пересоздан; разрешение прямого fallback не включается."));
  el("reconnect-warp").addEventListener("click", () => confirmedOperation("warp.reconnect", {}, "Переподключить WARP", "Переподключить WARP? Клиентские соединения могут прерваться. Действующая политика прямого выхода сохранится."));
  el("repair").addEventListener("click", () => confirmedOperation("repair", {}, "Восстановить маршруты", "Проверить и восстановить принадлежащие панели правила и маршруты? AWG не будет автоматически перезапущен; выбранная политика выхода сохраняется."));
  setInterval(async () => {
    if (!state.authenticated || document.hidden || state.polling) return;
    const active = state.operations.some((operation) => !terminalStatuses.has(operation.status));
    if (state.view !== "operations" && !active) return;
    state.polling = true;
    try { await loadOperations(); if (state.selectedOperation) await loadOperationDetails(state.selectedOperation); }
    catch (error) { showError(error); }
    finally { state.polling = false; }
  }, 3000);
  setInterval(() => { if (state.authenticated && !document.hidden && state.view === "overview") runWithError(loadOverview); }, 15000);
  api("/auth/me").then(signedIn).catch((error) => { if (error.status !== 401) el("login-error").textContent = error.message; });
})();
