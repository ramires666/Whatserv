"use strict";

const state = {
  token: "",
  csrfToken: "",
  dockhandUrl: "",
  environments: [],
  repositories: [],
  gitStacks: [],
  composeStacks: [],
  busy: false,
  connected: false,
  preflight: { ok: false, repository: null },
  confirmedFingerprint: "",
};

const elements = {
  workspace: document.querySelector("#workspace"),
  dockhandUrl: document.querySelector("#dockhand-url"),
  token: document.querySelector("#api-token"),
  connect: document.querySelector("#connect-button"),
  disconnect: document.querySelector("#disconnect-button"),
  connectionStatus: document.querySelector("#connection-status"),
  refresh: document.querySelector("#refresh-button"),
  deployForm: document.querySelector("#deploy-form"),
  environment: document.querySelector("#environment"),
  repositoryUrl: document.querySelector("#repository-url"),
  repositoryName: document.querySelector("#repository-name"),
  repositoryBranch: document.querySelector("#repository-branch"),
  stackName: document.querySelector("#stack-name"),
  composePath: document.querySelector("#compose-path"),
  envFilePath: document.querySelector("#env-file-path"),
  autoUpdate: document.querySelector("#auto-update"),
  preflight: document.querySelector("#preflight"),
  preflightButton: document.querySelector("#preflight-button"),
  createButton: document.querySelector("#create-button"),
  environmentCount: document.querySelector("#environment-count"),
  repositoryCount: document.querySelector("#repository-count"),
  gitStackCount: document.querySelector("#git-stack-count"),
  composeStackCount: document.querySelector("#compose-stack-count"),
  repositoriesBody: document.querySelector("#repositories-body"),
  gitStacksBody: document.querySelector("#git-stacks-body"),
  composeStacksBody: document.querySelector("#compose-stacks-body"),
  operationOutput: document.querySelector("#operation-output"),
  clearOutput: document.querySelector("#clear-output-button"),
  confirmDialog: document.querySelector("#confirm-dialog"),
  confirmTitle: document.querySelector("#confirm-title"),
  confirmDescription: document.querySelector("#confirm-description"),
  confirmLabel: document.querySelector("#confirm-label"),
  confirmInput: document.querySelector("#confirm-input"),
  confirmSubmit: document.querySelector("#confirm-submit"),
};

class ApiError extends Error {
  constructor(status, payload) {
    const message = payload?.error || payload?.message || `HTTP ${status}`;
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

function asArray(payload, keys = [], label = "ответа Dockhand") {
  if (Array.isArray(payload)) return payload;
  for (const key of [...keys, "items", "result"]) {
    if (Array.isArray(payload?.[key])) return payload[key];
  }
  if (Array.isArray(payload?.data)) return payload.data;
  throw new Error(`Неизвестный формат ${label}; операция остановлена для безопасности`);
}

function selectedEnvironmentId() {
  const value = Number(elements.environment.value);
  return Number.isInteger(value) && value > 0 ? value : null;
}

function setConnectionStatus(label, variant = "neutral") {
  elements.connectionStatus.textContent = label;
  elements.connectionStatus.className = `status-pill ${variant}`;
}

function setBusy(busy, label = "Выполняется…") {
  state.busy = busy;
  if (busy) setConnectionStatus(label, "busy");
  else if (state.connected) setConnectionStatus("Подключено", "good");
  document.querySelectorAll("button").forEach((button) => {
    if (button.closest("dialog")) return;
    if (button === elements.disconnect) {
      button.disabled = busy || !state.connected;
      return;
    }
    if (button === elements.connect) {
      button.disabled = busy || state.connected;
      return;
    }
    button.disabled = busy || !state.connected;
  });
  updatePreflight();
}

function safeJson(payload) {
  try {
    return JSON.stringify(payload, null, 2);
  } catch (_error) {
    return String(payload);
  }
}

function showOutput(title, status, payload) {
  const stamp = new Date().toLocaleString();
  elements.operationOutput.textContent = [
    `[${stamp}] ${title}`,
    status ? `HTTP ${status}` : "",
    payload === undefined ? "" : safeJson(payload),
  ].filter(Boolean).join("\n");
}

async function api(path, { method = "GET", body } = {}) {
  if (!state.token) throw new Error("Сначала подключитесь с API-токеном");
  const headers = {
    Accept: "application/json",
    Authorization: `Bearer ${state.token}`,
  };
  const options = { method, headers, cache: "no-store" };
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = state.csrfToken;
    options.body = body === undefined ? "{}" : JSON.stringify(body);
  }
  const response = await fetch(`/dockhand${path}`, options);
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (_error) {
      payload = { message: text };
    }
  }
  if (!response.ok) throw new ApiError(response.status, payload);
  return { status: response.status, payload };
}

function createCell(text, className = "") {
  const cell = document.createElement("td");
  cell.textContent = text ?? "—";
  if (className) cell.className = className;
  return cell;
}

function emptyRow(target, colspan, label) {
  const row = document.createElement("tr");
  const cell = createCell(label, "empty-row");
  cell.colSpan = colspan;
  row.append(cell);
  target.replaceChildren(row);
}

function actionButton(label, variant, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `button ${variant} small`;
  button.textContent = label;
  button.disabled = state.busy;
  button.addEventListener("click", handler);
  return button;
}

function getEnvironmentName(id) {
  const environment = state.environments.find((item) => Number(item.id) === Number(id));
  return environment?.name || `#${id ?? "?"}`;
}

function getRepositoryName(id) {
  const repository = state.repositories.find((item) => Number(item.id) === Number(id));
  return repository?.name || `#${id ?? "?"}`;
}

function stackEnvironmentId(stack) {
  const value = stack.environmentId ?? stack.environment_id ?? stack.env;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

function stacksForEnvironment(items, environmentId) {
  return items.filter((stack) => {
    const explicitEnvironment = stackEnvironmentId(stack);
    return explicitEnvironment === null || explicitEnvironment === Number(environmentId);
  });
}

function renderEnvironments(previousId = null) {
  const wanted = previousId || selectedEnvironmentId();
  const fragment = document.createDocumentFragment();
  for (const environment of state.environments) {
    const option = document.createElement("option");
    option.value = String(environment.id);
    option.textContent = `${environment.name} (#${environment.id})`;
    fragment.append(option);
  }
  elements.environment.replaceChildren(fragment);
  if (wanted && state.environments.some((item) => Number(item.id) === Number(wanted))) {
    elements.environment.value = String(wanted);
  }
}

function renderRepositories() {
  if (!state.repositories.length) {
    emptyRow(elements.repositoriesBody, 5, "Репозитории не зарегистрированы");
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const repository of state.repositories) {
    const row = document.createElement("tr");
    row.append(
      createCell(repository.id, "mono"),
      createCell(repository.name),
      createCell(repository.url, "mono truncate"),
      createCell(repository.branch || "main", "mono"),
    );
    const actionsCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "actions";
    actions.append(
      actionButton("Test", "ghost", () => runRepositoryAction(repository, "test")),
      actionButton("Sync", "ghost", () => runRepositoryAction(repository, "sync")),
      actionButton("Delete", "danger", () => deleteRepository(repository)),
    );
    actionsCell.append(actions);
    row.append(actionsCell);
    fragment.append(row);
  }
  elements.repositoriesBody.replaceChildren(fragment);
}

function renderGitStacks() {
  if (!state.gitStacks.length) {
    emptyRow(elements.gitStacksBody, 6, "Git stacks в выбранном environment отсутствуют");
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const stack of state.gitStacks) {
    const row = document.createElement("tr");
    const stackName = stack.stackName ?? stack.stack_name ?? stack.name;
    const environmentId = stackEnvironmentId(stack);
    const repositoryId = stack.repositoryId ?? stack.repository_id ?? stack.repository?.id;
    row.append(
      createCell(stack.id, "mono"),
      createCell(stackName),
      createCell(getEnvironmentName(environmentId)),
      createCell(stack.syncStatus ?? stack.sync_status ?? stack.status ?? "unknown", "mono"),
      createCell(stack.repository?.name ?? getRepositoryName(repositoryId)),
    );
    const actionsCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "actions";
    if (environmentId === null) {
      const blocked = actionButton("Environment unknown", "ghost", () => {});
      blocked.disabled = true;
      blocked.title = "Dockhand не вернул environmentId; действия заблокированы";
      actions.append(blocked);
    } else {
      actions.append(
        actionButton("Deploy", "secondary", () => runStackAction(stack, "deploy")),
        actionButton("Sync", "ghost", () => runStackAction(stack, "sync")),
        actionButton("Delete", "danger", () => deleteStack(stack)),
      );
    }
    actionsCell.append(actions);
    row.append(actionsCell);
    fragment.append(row);
  }
  elements.gitStacksBody.replaceChildren(fragment);
}

function composeName(stack) {
  return stack.name ?? stack.stackName ?? stack.stack_name ?? stack.projectName ?? stack.project_name ?? "unknown";
}

function renderComposeStacks() {
  if (!state.composeStacks.length) {
    emptyRow(elements.composeStacksBody, 3, "Compose stacks не найдены");
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const stack of state.composeStacks) {
    const row = document.createElement("tr");
    const config = stack.configFiles ?? stack.config_files ?? stack.configPath ?? stack.path ?? "—";
    row.append(
      createCell(composeName(stack)),
      createCell(stack.status ?? stack.state ?? "unknown", "mono"),
      createCell(Array.isArray(config) ? config.join(", ") : config, "mono truncate"),
    );
    fragment.append(row);
  }
  elements.composeStacksBody.replaceChildren(fragment);
}

function renderCounts() {
  elements.environmentCount.textContent = String(state.environments.length);
  elements.repositoryCount.textContent = String(state.repositories.length);
  elements.gitStackCount.textContent = String(state.gitStacks.length);
  elements.composeStackCount.textContent = String(state.composeStacks.length);
}

function renderAll() {
  renderRepositories();
  renderGitStacks();
  renderComposeStacks();
  renderCounts();
  updatePreflight();
}

function normalizedRemote(rawValue) {
  const raw = String(rawValue || "").trim();
  if (!raw) return "";
  const sshMatch = raw.match(/^git@([^:]+):(.+)$/i);
  const candidate = sshMatch ? `https://${sshMatch[1]}/${sshMatch[2]}` : raw;
  try {
    const parsed = new URL(candidate);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    const path = parsed.pathname.replace(/\.git$/i, "").replace(/\/+$/, "");
    return `${parsed.hostname.toLowerCase()}${path}`.toLowerCase();
  } catch (_error) {
    return raw.replace(/\.git$/i, "").replace(/\/+$/, "").toLowerCase();
  }
}

function formFingerprint() {
  return JSON.stringify({
    environment: elements.environment.value,
    repositoryUrl: elements.repositoryUrl.value.trim(),
    repositoryName: elements.repositoryName.value.trim(),
    branch: elements.repositoryBranch.value.trim(),
    stackName: elements.stackName.value.trim(),
    composePath: elements.composePath.value.trim(),
    envFilePath: elements.envFilePath.value.trim(),
    autoUpdate: elements.autoUpdate.checked,
  });
}

function updatePreflight({ confirm = false } = {}) {
  const environmentId = selectedEnvironmentId();
  const repositoryName = elements.repositoryName.value.trim();
  const repositoryUrl = elements.repositoryUrl.value.trim();
  const branch = elements.repositoryBranch.value.trim();
  const stackName = elements.stackName.value.trim();
  const composePath = elements.composePath.value.trim();
  const failures = [];
  const warnings = [];

  if (!state.connected) failures.push("Сначала подключитесь к Dockhand.");
  if (!environmentId) failures.push("Выберите environment.");
  if (!repositoryName || !repositoryUrl || !branch || !stackName || !composePath) {
    failures.push("Заполните обязательные поля.");
  }

  const normalizedUrl = normalizedRemote(repositoryUrl);
  const repositoryByRemote = state.repositories.find((repository) =>
    normalizedRemote(repository.url) === normalizedUrl &&
    String(repository.branch || "main") === branch
  );
  const repositoryByName = state.repositories.find((repository) =>
    String(repository.name).toLowerCase() === repositoryName.toLowerCase()
  );
  if (repositoryByName && repositoryByName !== repositoryByRemote) {
    failures.push(`Имя repository «${repositoryName}» уже связано с другим URL или branch.`);
  }
  if (repositoryByRemote) warnings.push(`Будет использован существующий repository #${repositoryByRemote.id}.`);

  const existingGitStack = state.gitStacks.find((stack) => {
    const name = stack.stackName ?? stack.stack_name ?? stack.name;
    const env = stackEnvironmentId(stack);
    return String(name).toLowerCase() === stackName.toLowerCase() && env === environmentId;
  });
  if (existingGitStack) failures.push(`Git Stack «${stackName}» уже существует: ID ${existingGitStack.id}.`);
  const unknownEnvironmentCollision = state.gitStacks.find((stack) => {
    const name = stack.stackName ?? stack.stack_name ?? stack.name;
    return String(name).toLowerCase() === stackName.toLowerCase() && stackEnvironmentId(stack) === null;
  });
  if (unknownEnvironmentCollision) {
    warnings.push(`Dockhand не вернул environment для stack «${stackName}»; автоматическая проверка этой коллизии неполна.`);
  }

  const existingComposeStack = state.composeStacks.find((stack) => {
    const env = stackEnvironmentId(stack);
    return String(composeName(stack)).toLowerCase() === stackName.toLowerCase() &&
      env === environmentId;
  });
  if (existingComposeStack) failures.push(`Имя «${stackName}» занято обычным Compose stack.`);
  const unknownComposeCollision = state.composeStacks.find((stack) =>
    String(composeName(stack)).toLowerCase() === stackName.toLowerCase() &&
    stackEnvironmentId(stack) === null
  );
  if (unknownComposeCollision) {
    warnings.push(`Dockhand не вернул environment для Compose stack «${stackName}»; автоматическая проверка этой коллизии неполна.`);
  }

  state.preflight = {
    ok: failures.length === 0,
    repository: repositoryByRemote || null,
    environmentId,
  };

  const fingerprint = formFingerprint();
  if (confirm && failures.length === 0) state.confirmedFingerprint = fingerprint;
  const explicitlyConfirmed = state.confirmedFingerprint === fingerprint;

  if (failures.length) {
    elements.preflight.className = "preflight bad";
    elements.preflight.textContent = failures.join(" ");
  } else if (warnings.length) {
    elements.preflight.className = "preflight warn";
    elements.preflight.textContent = `${warnings.join(" ")} ${explicitlyConfirmed ? "Проверка подтверждена." : "Нажмите «Проверить» перед созданием."}`;
  } else {
    elements.preflight.className = explicitlyConfirmed ? "preflight good" : "preflight neutral";
    elements.preflight.textContent = explicitlyConfirmed
      ? "Проверка подтверждена. Dockhand получит ровно один запрос создания и развёртывания."
      : "Конфликтов не найдено. Нажмите «Проверить», затем подтвердите создание.";
  }
  elements.createButton.disabled = state.busy || !state.preflight.ok || !explicitlyConfirmed;
  return state.preflight;
}

async function refreshAll({ preserveEnvironment = true } = {}) {
  const previousEnvironment = preserveEnvironment ? selectedEnvironmentId() : null;
  const [environmentResponse, repositoryResponse] = await Promise.all([
    api("/api/environments"),
    api("/api/git/repositories"),
  ]);
  state.environments = asArray(environmentResponse.payload, ["environments"], "списка environments");
  state.repositories = asArray(repositoryResponse.payload, ["repositories"], "списка repositories");
  renderEnvironments(previousEnvironment);

  const environmentId = selectedEnvironmentId();
  if (!environmentId) {
    state.gitStacks = [];
    state.composeStacks = [];
    renderAll();
    return;
  }
  const [gitResponse, composeResponse] = await Promise.all([
    api(`/api/git/stacks?env=${environmentId}`),
    api(`/api/stacks?env=${environmentId}`),
  ]);
  state.gitStacks = stacksForEnvironment(
    asArray(gitResponse.payload, ["stacks", "gitStacks"], "списка Git stacks"),
    environmentId,
  );
  state.composeStacks = stacksForEnvironment(
    asArray(composeResponse.payload, ["stacks"], "списка Compose stacks"),
    environmentId,
  );
  renderAll();
}

async function connect() {
  const token = elements.token.value.trim();
  if (!/^dh_[A-Za-z0-9_-]{20,}$/.test(token)) {
    setConnectionStatus("Некорректный token", "bad");
    elements.token.focus();
    return;
  }
  state.token = token;
  elements.token.value = "";
  state.connected = false;
  setBusy(true, "Подключение…");
  try {
    await refreshAll({ preserveEnvironment: false });
    state.connected = true;
    elements.workspace.hidden = false;
    setConnectionStatus("Подключено", "good");
    showOutput("Подключение", 200, {
      dockhand: state.dockhandUrl,
      environments: state.environments.length,
      tokenStorage: "memory-only",
    });
  } catch (error) {
    state.token = "";
    state.connected = false;
    elements.workspace.hidden = true;
    setConnectionStatus(`Ошибка: ${error.message}`, "bad");
    showOutput("Ошибка подключения", error.status, error.payload || { error: error.message });
  } finally {
    setBusy(false);
  }
}

function disconnect() {
  state.token = "";
  state.connected = false;
  state.environments = [];
  state.repositories = [];
  state.gitStacks = [];
  state.composeStacks = [];
  elements.workspace.hidden = true;
  elements.token.value = "";
  setConnectionStatus("Не подключено", "neutral");
  setBusy(false);
  elements.token.focus();
}

async function runOperation(title, operation) {
  if (state.busy) return null;
  setBusy(true, title);
  let result;
  try {
    result = await operation();
  } catch (error) {
    showOutput(title, error.status, error.payload || { error: error.message });
    try {
      await refreshAll();
    } catch (_refreshError) {
      // The mutation result may be unknown. Never retry it automatically.
    }
    setBusy(false);
    setConnectionStatus(`Ошибка HTTP ${error.status || "?"}`, "bad");
    return null;
  }

  showOutput(title, result.status, result.payload);
  let refreshError = null;
  try {
    await refreshAll();
  } catch (error) {
    refreshError = error;
    showOutput(`${title} — выполнено, но список не обновлён`, result.status, {
      result: result.payload,
      refreshError: error.payload || { error: error.message },
      action: "Нажмите «Обновить данные». Не повторяйте mutation вслепую.",
    });
  } finally {
    setBusy(false);
  }
  if (refreshError) setConnectionStatus("Выполнено; обновите данные", "warn");
  return result;
}

async function createGitStack(event) {
  event.preventDefault();
  if (!elements.deployForm.reportValidity()) return;
  const check = updatePreflight();
  if (!check.ok || state.busy || state.confirmedFingerprint !== formFingerprint()) return;

  const fingerprint = state.confirmedFingerprint;
  const stackName = elements.stackName.value.trim();
  const confirmed = await confirmDestructive({
    title: "Создать и развернуть Git Stack?",
    description: "Dockhand получит один запрос создания. Он клонирует repository и запустит Docker Compose.",
    expected: stackName,
    submitLabel: "Создать",
  });
  if (!confirmed || fingerprint !== formFingerprint()) return;

  // Invalidate before the mutation. A lost response or failed refresh must never
  // leave a one-click path to sending the same create request again.
  state.confirmedFingerprint = "";
  updatePreflight();

  const result = await runOperation("Создание и развёртывание Git Stack", async () => {
    let repository = check.repository;
    if (!repository) {
      const created = await api("/api/git/repositories", {
        method: "POST",
        body: {
          name: elements.repositoryName.value.trim(),
          url: elements.repositoryUrl.value.trim(),
          branch: elements.repositoryBranch.value.trim(),
        },
      });
      repository = created.payload?.repository ?? created.payload;
      if (!repository?.id) {
        const refreshed = await api("/api/git/repositories");
        const repositories = asArray(refreshed.payload, ["repositories"], "списка repositories");
        repository = repositories.find((item) =>
          normalizedRemote(item.url) === normalizedRemote(elements.repositoryUrl.value) &&
          String(item.branch || "main") === elements.repositoryBranch.value.trim()
        );
      }
      if (!repository?.id) throw new Error("Dockhand создал repository, но не вернул его ID");
    }

    const payload = {
      stackName,
      repositoryId: Number(repository.id),
      environmentId: check.environmentId,
      composePath: elements.composePath.value.trim(),
      autoUpdate: elements.autoUpdate.checked,
    };
    const envFilePath = elements.envFilePath.value.trim();
    if (envFilePath) payload.envFilePath = envFilePath;
    return api("/api/git/stacks", { method: "POST", body: payload });
  });
  if (result) updatePreflight();
}

async function runRepositoryAction(repository, action) {
  await runOperation(`${action} repository ${repository.name}`, () =>
    api(`/api/git/repositories/${repository.id}/${action}`, { method: "POST" })
  );
}

async function runStackAction(stack, action) {
  const name = stack.stackName ?? stack.stack_name ?? stack.name;
  const environmentId = stackEnvironmentId(stack);
  if (!environmentId) {
    showOutput(`${action} Git Stack ${name} заблокирован`, 409, {
      error: "Dockhand не вернул environmentId для этого stack",
    });
    return;
  }
  const confirmed = await confirmDestructive({
    title: action === "deploy" ? "Развернуть Git Stack?" : "Синхронизировать Git Stack?",
    description: action === "deploy"
      ? `Dockhand пересоздаст или обновит workload Git Stack #${stack.id}.`
      : `Dockhand синхронизирует Git и может развернуть найденные изменения для Stack #${stack.id}.`,
    expected: name,
    submitLabel: action === "deploy" ? "Deploy" : "Sync",
  });
  if (!confirmed) return;
  await runOperation(`${action} Git Stack ${name}`, () =>
    api(`/api/git/stacks/${stack.id}/${action}?env=${environmentId}`, { method: "POST" })
  );
}

function confirmDestructive({ title, description, expected, submitLabel = "Удалить" }) {
  return new Promise((resolve) => {
    elements.confirmTitle.textContent = title;
    elements.confirmDescription.textContent = description;
    elements.confirmLabel.textContent = `Введите «${expected}» для подтверждения`;
    elements.confirmInput.value = "";
    elements.confirmSubmit.textContent = submitLabel;
    elements.confirmSubmit.disabled = true;
    const onInput = () => {
      elements.confirmSubmit.disabled = elements.confirmInput.value !== expected;
    };
    elements.confirmInput.addEventListener("input", onInput);
    elements.confirmDialog.showModal();
    elements.confirmInput.focus();
    const onClose = () => {
      const accepted = elements.confirmDialog.returnValue === "confirm" &&
        elements.confirmInput.value === expected;
      elements.confirmDialog.removeEventListener("close", onClose);
      elements.confirmInput.removeEventListener("input", onInput);
      resolve(accepted);
    };
    elements.confirmDialog.addEventListener("close", onClose);
  });
}

async function deleteRepository(repository) {
  if (state.busy) return;
  setBusy(true, "Проверка зависимостей…");
  let allGitStacks = [];
  try {
    const responses = await Promise.all(state.environments.map((environment) =>
      api(`/api/git/stacks?env=${environment.id}`)
    ));
    const byId = new Map();
    for (const response of responses) {
      for (const stack of asArray(response.payload, ["stacks", "gitStacks"], "списка Git stacks")) {
        byId.set(String(stack.id), stack);
      }
    }
    allGitStacks = [...byId.values()];
  } catch (error) {
    showOutput("Проверка зависимостей repository", error.status, error.payload || { error: error.message });
    setBusy(false);
    return;
  }
  setBusy(false);
  const dependencies = allGitStacks.filter((stack) =>
    Number(stack.repositoryId ?? stack.repository_id ?? stack.repository?.id) === Number(repository.id)
  );
  if (dependencies.length) {
    showOutput("Удаление repository заблокировано", 409, {
      repository: repository.name,
      dependentStacks: dependencies.map((stack) => ({
        id: stack.id,
        name: stack.stackName ?? stack.stack_name ?? stack.name,
        environmentId: stackEnvironmentId(stack),
      })),
    });
    return;
  }
  const confirmed = await confirmDestructive({
    title: "Удалить repository?",
    description: `Будет удалена регистрация repository #${repository.id}. Git stacks автоматически не удаляются.`,
    expected: repository.name,
    submitLabel: "Удалить",
  });
  if (!confirmed) return;
  await runOperation(`Удаление repository ${repository.name}`, () =>
    api(`/api/git/repositories/${repository.id}`, { method: "DELETE" })
  );
}

async function deleteStack(stack) {
  const name = stack.stackName ?? stack.stack_name ?? stack.name;
  const environmentId = stackEnvironmentId(stack);
  if (!environmentId) {
    showOutput(`Удаление Git Stack ${name} заблокировано`, 409, {
      error: "Dockhand не вернул environmentId для этого stack",
    });
    return;
  }
  const confirmed = await confirmDestructive({
    title: "Удалить Git Stack?",
    description: `Будет удалён Git Stack #${stack.id} в environment ${getEnvironmentName(environmentId)}. Volumes автоматически не подтверждаются этим инструментом.`,
    expected: name,
    submitLabel: "Удалить",
  });
  if (!confirmed) return;
  await runOperation(`Удаление Git Stack ${name}`, () =>
    api(`/api/git/stacks/${stack.id}?env=${environmentId}`, { method: "DELETE" })
  );
}

async function initialize() {
  try {
    const response = await fetch("/config", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const config = await response.json();
    state.csrfToken = config.csrfToken;
    state.dockhandUrl = config.dockhandUrl;
    elements.dockhandUrl.value = config.dockhandUrl;
    elements.token.focus();
  } catch (error) {
    setConnectionStatus(`Не удалось загрузить конфигурацию: ${error.message}`, "bad");
    elements.connect.disabled = true;
  }
}

elements.connect.addEventListener("click", connect);
elements.disconnect.addEventListener("click", disconnect);
elements.refresh.addEventListener("click", () => runOperation("Обновление данных", async () => {
  await refreshAll();
  return { status: 200, payload: { refreshed: true } };
}));
elements.environment.addEventListener("change", () => runOperation("Смена environment", async () => {
  const environmentId = selectedEnvironmentId();
  const [gitResponse, composeResponse] = await Promise.all([
    api(`/api/git/stacks?env=${environmentId}`),
    api(`/api/stacks?env=${environmentId}`),
  ]);
  state.gitStacks = stacksForEnvironment(
    asArray(gitResponse.payload, ["stacks", "gitStacks"], "списка Git stacks"),
    environmentId,
  );
  state.composeStacks = stacksForEnvironment(
    asArray(composeResponse.payload, ["stacks"], "списка Compose stacks"),
    environmentId,
  );
  renderAll();
  return { status: 200, payload: { environmentId } };
}));
elements.deployForm.addEventListener("submit", createGitStack);
elements.preflightButton.addEventListener("click", () => updatePreflight({ confirm: true }));
elements.deployForm.addEventListener("input", () => updatePreflight());
elements.clearOutput.addEventListener("click", () => {
  elements.operationOutput.textContent = "Операций пока не было.";
});
elements.token.addEventListener("keydown", (event) => {
  if (event.key === "Enter") connect();
});
window.addEventListener("beforeunload", () => {
  state.token = "";
});

initialize();
