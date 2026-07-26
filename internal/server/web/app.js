const state = { csrf: "", settings: null, probe: null, system: null, license: null, currentRun: null, grids: {} };
const $ = id => document.getElementById(id);
const escapeHTML = value => String(value ?? "").replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[char]));
const formatDate = value => {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) || date.getFullYear() < 2000 ? "—" : date.toLocaleString();
};
const toast = (message, error = false) => {
  const element = $("toast");
  element.textContent = message;
  element.className = `toast show${error ? " error" : ""}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.className = "toast", 4800);
};

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.csrf && options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  let body = {};
  try { body = await response.json(); } catch {}
  if (!response.ok) {
    const message = body?.error?.message || body?.error_description || `HTTP ${response.status}`;
    if (response.status === 401) showAuth(true);
    throw new Error(message);
  }
  return body;
}

function showAuth(setup) {
  $("authLayer").classList.remove("hidden");
  $("authTitle").textContent = setup ? "初始化 NASLink" : "管理身份验证";
  $("authDescription").textContent = setup ? "设置一个至少 12 位、仅用于本插件的管理密码。" : "输入 NASLink 本地管理员密码。";
  $("authForm").dataset.mode = setup ? "setup" : "login";
  $("logoutButton").classList.add("hidden");
  setTimeout(() => $("adminPassword").focus(), 60);
}

function hideAuth() {
  $("authLayer").classList.add("hidden");
  $("logoutButton").classList.remove("hidden");
}

async function boot() {
  try {
    const status = await api("/api/v1/status");
    $("runtimeDot").classList.add("online");
    $("runtimeText").textContent = `服务在线 · ${status.version}`;
    showAuth(!status.setup_complete);
  } catch (error) {
    $("runtimeText").textContent = "服务不可用";
    toast(error.message, true);
  }
}

$("authForm").addEventListener("submit", async event => {
  event.preventDefault();
  const setup = event.currentTarget.dataset.mode === "setup";
  try {
    const result = await api(setup ? "/api/v1/setup" : "/api/v1/session", { method: "POST", body: JSON.stringify({ password: $("adminPassword").value }) });
    state.csrf = result.csrf_token;
    $("adminPassword").value = "";
    hideAuth();
    await Promise.all([loadSettings(), loadSystem(), loadLicense()]);
    toast(setup ? "NASLink 管理员初始化完成" : "已进入管理后台");
  } catch (error) { toast(error.message, true); }
});

$("logoutButton").addEventListener("click", async () => {
  try { await api("/api/v1/session", { method: "DELETE" }); } catch {}
  state.csrf = "";
  showAuth(false);
});

function redrawVisibleGrids() {
  requestAnimationFrame(() => Object.values(state.grids).forEach(grid => {
    if (!grid?._naslinkReady || !grid.element?.isConnected || !grid.element.offsetParent) return;
    grid.redraw(true);
  }));
}

function activatePage(target) {
  const button = document.querySelector(`.nav-item[data-target="${CSS.escape(target)}"]`);
  if (!button || !$(target)) return;
  document.querySelectorAll(".nav-item,.panel").forEach(element => element.classList.remove("active"));
  button.classList.add("active");
  $(target).classList.add("active");
  $("adminRail").classList.remove("is-open");
  $("mobileNavToggle").setAttribute("aria-expanded", "false");
  $("mobileNavToggle").setAttribute("aria-label", "打开管理导航");
  window.scrollTo(0, 0);
  redrawVisibleGrids();
}

document.querySelectorAll(".nav-item").forEach(button => button.addEventListener("click", () => activatePage(button.dataset.target)));

$("mobileNavToggle").addEventListener("click", () => {
  const open = !$("adminRail").classList.contains("is-open");
  $("adminRail").classList.toggle("is-open", open);
  $("mobileNavToggle").setAttribute("aria-expanded", String(open));
  $("mobileNavToggle").setAttribute("aria-label", open ? "关闭管理导航" : "打开管理导航");
});

async function loadSettings() {
  state.settings = await api("/api/v1/settings");
  const settings = state.settings;
  const hasDSMAddress = Boolean(settings.dsm.base_url);
  $("dsmBaseURL").value = settings.dsm.base_url || "https://127.0.0.1:5001";
  $("dsmAccount").value = settings.dsm.account || "";
  $("dsmPassword").placeholder = settings.dsm.has_password ? "已保存，留空保持原值" : "请输入 DSM 管理密码";
  $("dsmInsecure").checked = hasDSMAddress ? settings.dsm.insecure_tls : true;
  $("mutationPrefix").value = settings.dsm.mutation_prefix || "naslink_poc_";
  $("prefixHint").textContent = $("mutationPrefix").value;
  $("dingClientID").value = settings.dingtalk.client_id || "";
  $("dingClientSecret").placeholder = settings.dingtalk.has_client_secret ? "已保存，留空保持原值" : "请输入 Client Secret";
  $("dingAuthURL").value = settings.dingtalk.auth_url || "https://login.dingtalk.com/oauth2/auth";
  $("dingAPIBase").value = settings.dingtalk.api_base_url || "https://api.dingtalk.com";
	$("wecomCorpID").value = settings.wecom?.corp_id || "";
	$("wecomAgentID").value = settings.wecom?.agent_id || "";
	$("wecomSecret").placeholder = settings.wecom?.has_secret ? "已保存，留空保持原值" : "请输入 Secret";
	$("wecomAuthURL").value = settings.wecom?.auth_url || "https://open.work.weixin.qq.com/wwopen/sso/qrConnect";
	$("wecomInAppAuthURL").value = settings.wecom?.in_app_auth_url || "https://open.weixin.qq.com/connect/oauth2/authorize";
	$("wecomDriveWebURL").value = settings.wecom?.drive_web_url || "";
	$("wecomAPIBase").value = settings.wecom?.api_base_url || "https://qyapi.weixin.qq.com";
  $("oidcIssuer").value = settings.oidc.issuer || "";
  $("oidcClientID").value = settings.oidc.client_id || "";
  $("oidcRedirectURI").value = settings.oidc.redirect_uris?.[0] || "";
  $("discoveryURL").textContent = settings.oidc.discovery_url || "保存 Issuer 后生成";
	$("wecomCallbackURL").textContent = settings.oidc.issuer ? `${settings.oidc.issuer.replace(/\/$/, "")}/events/wecom` : "保存 Issuer 后生成";
	$("wecomLaunchURL").textContent = settings.wecom?.launch_url || "保存 Issuer 后生成";
	$("licenseCenterURL").value = settings.license_center?.url || "";
	renderSourcePanels(settings.identity_source || "dingtalk");
  renderBindings(settings.bindings || []);
}

function settingsPayload() {
  return {
	identity_source: $("identitySource").value,
    dsm: { base_url: $("dsmBaseURL").value.trim(), account: $("dsmAccount").value.trim(), password: $("dsmPassword").value, insecure_tls: $("dsmInsecure").checked, mutation_prefix: $("mutationPrefix").value.trim() },
	dingtalk: { client_id: $("dingClientID").value.trim(), client_secret: $("dingClientSecret").value, auth_url: $("dingAuthURL").value.trim(), api_base_url: $("dingAPIBase").value.trim(), event_token: $("dingEventToken").value },
	wecom: { corp_id: $("wecomCorpID").value.trim(), agent_id: $("wecomAgentID").value.trim(), secret: $("wecomSecret").value, auth_url: $("wecomAuthURL").value.trim(), in_app_auth_url: $("wecomInAppAuthURL").value.trim(), drive_web_url: $("wecomDriveWebURL").value.trim(), api_base_url: $("wecomAPIBase").value.trim(), callback_token: $("wecomCallbackToken").value, callback_aes_key: $("wecomCallbackAESKey").value },
    oidc: { issuer: $("oidcIssuer").value.trim(), client_id: $("oidcClientID").value.trim(), client_secret: $("oidcClientSecret").value, redirect_uris: [$("oidcRedirectURI").value.trim()].filter(Boolean) }
	,license_center: { url: $("licenseCenterURL").value.trim(), activation_code: $("activationCode").value }
  };
}

$("saveSettings").addEventListener("click", async () => {
  try {
    state.settings = await api("/api/v1/settings", { method: "PUT", body: JSON.stringify(settingsPayload()) });
	["dsmPassword","dingClientSecret","dingEventToken","wecomSecret","wecomCallbackToken","wecomCallbackAESKey","oidcClientSecret","activationCode"].forEach(id => $(id).value = "");
    $("discoveryURL").textContent = state.settings.oidc.discovery_url || "保存 Issuer 后生成";
    $("prefixHint").textContent = state.settings.dsm.mutation_prefix;
	renderSourcePanels(state.settings.identity_source);
	$("wecomCallbackURL").textContent = state.settings.oidc.issuer ? `${state.settings.oidc.issuer.replace(/\/$/, "")}/events/wecom` : "保存 Issuer 后生成";
	$("wecomLaunchURL").textContent = state.settings.wecom?.launch_url || "保存 Issuer 后生成";
	toast("配置已加密保存");
  } catch (error) { toast(error.message, true); }
});

$("copyWeComLaunch").addEventListener("click", async () => {
	const value = $("wecomLaunchURL").textContent;
	if (!value || value.includes("保存 Issuer")) return toast("请先保存 OIDC Issuer", true);
	try {
		await navigator.clipboard.writeText(value);
		toast("企业微信自建应用主页地址已复制");
	} catch { toast("浏览器未允许复制，请手动选择地址", true); }
});

async function probe(options = {}) {
  const silent = Boolean(options?.silent);
  if (!silent) toast("正在连接 DSM 并执行只读盘点…");
  try {
    state.probe = await api("/api/v1/dsm/probe", { method: "POST", body: "{}" });
    renderProbe(state.probe);
    renderSyncReadiness();
    if (!silent) toast(`盘点完成：${state.probe.user_count} 个用户，${state.probe.group_count} 个群组`);
    return state.probe;
  } catch (error) {
    if (!silent) toast(error.message, true);
    throw error;
  }
}

$("probeDSM").addEventListener("click", probe);
$("refreshDirectory").addEventListener("click", probe);
$("testIdentity").addEventListener("click", async () => {
  toast("正在验证当前身份源应用凭据…");
  try {
	const sourceType = $("identitySource").value;
	const draftSecret = sourceType === "wecom" ? $("wecomSecret").value : $("dingClientSecret").value;
	const payload = sourceType === "wecom"
		? { source_type: "wecom", wecom: { corp_id: $("wecomCorpID").value.trim(), agent_id: $("wecomAgentID").value.trim(), secret: draftSecret, auth_url: $("wecomAuthURL").value.trim(), in_app_auth_url: $("wecomInAppAuthURL").value.trim(), api_base_url: $("wecomAPIBase").value.trim() } }
		: { source_type: "dingtalk", dingtalk: { client_id: $("dingClientID").value.trim(), client_secret: draftSecret, auth_url: $("dingAuthURL").value.trim(), api_base_url: $("dingAPIBase").value.trim() } };
	const result = await api("/api/v1/identity/test", { method: "POST", body: JSON.stringify(payload) });
	const saveHint = draftSecret ? "；验证通过，请点击右上角保存配置" : "";
	toast(`${result.source_type === "wecom" ? "企业微信" : "钉钉"}凭据有效，Token 有效期 ${result.token_expires_in} 秒${saveHint}`);
  } catch (error) { toast(error.message, true); }
});

const dingTalkCheckOrder = [
	{ key: "credentials", label: "应用凭据", required: true, message: "验证 Client ID 与 Client Secret" },
	{ key: "departments", label: "部门读取权限", required: true, message: "检查部门接口与应用可见范围" },
	{ key: "users", label: "员工读取权限", required: true, message: "检查员工接口与在职状态" },
	{ key: "matching_fields", label: "账号匹配字段", required: false, message: "工号、邮箱或手机号可提高历史账号匹配准确率" },
	{ key: "stream", label: "人员变动事件", required: false, message: "检查 NASLink Stream 长连接状态" }
];

function renderDingTalkDiagnostics(result) {
	const diagnostics = result?.diagnostics || {};
	const checks = new Map((diagnostics.checks || []).map(check => [check.key, check]));
	const statusLabels = { pass: "通过", warning: "需确认", error: "未通过", pending: "检测中", blocked: "待检测" };
	$("dingPermissionChecks").innerHTML = dingTalkCheckOrder.map(defaultCheck => {
		const check = { status: "blocked", ...defaultCheck, ...(checks.get(defaultCheck.key) || {}) };
		const requirement = check.required ? "必需" : "建议";
		return `<div class="permission-check" data-state="${escapeHTML(check.status)}"><i aria-hidden="true"></i><div><strong>${escapeHTML(check.label)}</strong><small>${escapeHTML(check.message)}</small></div><span>${requirement} · ${statusLabels[check.status] || "待检测"}</span></div>`;
	}).join("");
	$("dingVisibleDepartments").textContent = Number.isFinite(diagnostics.departments_visible) ? diagnostics.departments_visible : "—";
	$("dingVisibleUsers").textContent = Number.isFinite(diagnostics.users_visible) ? diagnostics.users_visible : "—";
	$("dingActiveUsers").textContent = Number.isFinite(diagnostics.active_users) ? diagnostics.active_users : "—";
	const statuses = [...checks.values()].map(check => check.status);
	const failed = statuses.includes("error");
	const needsReview = statuses.includes("warning") || statuses.includes("pending");
	$("dingDiagnosticSummary").textContent = failed ? "存在未通过项" : diagnostics.ok ? (needsReview ? "基础权限通过，仍有建议项" : "接入检查通过") : "尚未检测";
	$("dingDiagnosticMeta").textContent = result?.stream?.checked_at ? `Stream 状态更新于 ${new Date(result.stream.checked_at).toLocaleString()}` : "填写或保存凭据后执行只读检测";
}

renderDingTalkDiagnostics(null);

$("diagnoseDingTalk").addEventListener("click", async () => {
	const button = $("diagnoseDingTalk");
	button.disabled = true;
	button.setAttribute("aria-busy", "true");
	button.textContent = "正在检测…";
	$("dingDiagnosticSummary").textContent = "正在读取钉钉权限与可见范围";
	try {
		const result = await api("/api/v1/dingtalk/diagnose", { method: "POST", body: JSON.stringify({
			source_type: "dingtalk",
			dingtalk: { client_id: $("dingClientID").value.trim(), client_secret: $("dingClientSecret").value, auth_url: $("dingAuthURL").value.trim(), api_base_url: $("dingAPIBase").value.trim() }
		}) });
		renderDingTalkDiagnostics(result);
	} catch (error) {
		$("dingDiagnosticSummary").textContent = "检测请求失败";
		$("dingDiagnosticMeta").textContent = error.message;
		toast(error.message, true);
	} finally {
		button.disabled = false;
		button.removeAttribute("aria-busy");
		button.textContent = "重新检测";
	}
});

const gridCountTargets = { dsmUsers: "dsmUserGridCount", dsmGroups: "dsmGroupGridCount", departments: "departmentGridCount", sourceUsers: "sourceUserGridCount", matches: "matchGridCount" };
const gridCountUnits = { dsmUsers: "个账号", dsmGroups: "个群组", departments: "个部门", sourceUsers: "人", matches: "条匹配" };
const emptyFormatter = cell => escapeHTML(cell.getValue() || "—");

function updateGridCount(name, rows) {
  const target = $(gridCountTargets[name]);
  if (target) target.textContent = `${rows.length} ${gridCountUnits[name]}`;
}

function upsertGrid(name, elementID, data, columns) {
  if (!window.Tabulator) {
    toast("表格组件未加载，请刷新页面", true);
    return null;
  }
  if (state.grids[name]) {
    state.grids[name].replaceData(data);
    updateGridCount(name, data);
    return state.grids[name];
  }
  const gridIndexes = { dsmUsers: "name", dsmGroups: "name", departments: "id", sourceUsers: "subject", matches: "subject" };
  const grid = new Tabulator(`#${elementID}`, {
    data,
    columns,
    index: gridIndexes[name],
    layout: "fitColumns",
    responsiveLayout: "collapse",
    responsiveLayoutCollapseStartOpen: false,
    rowHeader: { formatter: "responsiveCollapse", width: 40, minWidth: 40, hozAlign: "center", resizable: false, headerSort: false },
    pagination: true,
    paginationMode: "local",
    paginationSize: 15,
    paginationSizeSelector: [15, 30, 50, 100],
    paginationCounter: "rows",
    movableColumns: false,
    placeholder: "当前条件下没有数据",
    langs: { "zh-cn": { pagination: { page_size: "每页", first: "首页", first_title: "首页", last: "末页", last_title: "末页", prev: "上一页", prev_title: "上一页", next: "下一页", next_title: "下一页", all: "全部", counter: { showing: "显示", of: "/", rows: "条", pages: "页" } } } },
    locale: "zh-cn"
  });
  grid._naslinkReady = false;
  grid.on("tableBuilt", () => {
    grid._naslinkReady = true;
    if (grid._naslinkPendingFilter) {
      const pending = grid._naslinkPendingFilter;
      grid._naslinkPendingFilter = null;
      grid.setFilter(pending);
    }
  });
  grid.on("dataFiltered", (_filters, rows) => updateGridCount(name, rows));
  state.grids[name] = grid;
  updateGridCount(name, data);
  return grid;
}

function applyFilter(name, predicate) {
  const grid = state.grids[name];
  if (!grid) return;
  if (!grid._naslinkReady) {
    grid._naslinkPendingFilter = predicate;
    return;
  }
  grid.setFilter(predicate);
  Promise.resolve(grid.setPage(1)).catch(() => {});
}

function normalized(value) { return String(value || "").trim().toLocaleLowerCase(); }

function applyDSMUserFilter() {
  const query = normalized($("dsmUserSearch").value);
  const status = $("dsmUserStatusFilter").value;
  applyFilter("dsmUsers", user => (!status || user.status === status) && (!query || normalized([user.name, user.email, user.description, user.group_text].join(" ")).includes(query)));
}

function applyDSMGroupFilter() {
  const query = normalized($("dsmGroupSearch").value);
  applyFilter("dsmGroups", group => !query || normalized([group.name, group.description, group.gid].join(" ")).includes(query));
}

function applyDepartmentFilter() {
  const query = normalized($("departmentSearch").value);
  const scope = $("departmentScopeFilter").value;
  applyFilter("departments", department => (!scope || department.scope === scope) && (!query || normalized([department.name, department.id, department.parent_name, department.leader_names, department.proposed_group].join(" ")).includes(query)));
}

function applySourceUserFilter() {
  const query = normalized($("sourceUserSearch").value);
  const scope = $("sourceUserScopeFilter").value;
  applyFilter("sourceUsers", user => (!scope || user.scope === scope) && (!query || normalized([user.name, user.employee_no, user.user_id, user.email, user.mobile, user.department_names].join(" ")).includes(query)));
}

function applyMatchFilter() {
  const query = normalized($("matchSearch").value);
  const status = $("matchStatusFilter").value;
  applyFilter("matches", match => (!status || match.status === status) && (!query || normalized([match.source_name, match.source_identity, match.dsm_username, match.reason_text].join(" ")).includes(query)));
}

function suggestedGroupName(departmentID) {
  const safe = String(departmentID || "").replace(/[^a-zA-Z0-9_-]+/g, "_").replace(/^_+|_+$/g, "").slice(-48);
  return `dept_${safe || "group"}`;
}

$("dsmUserSearch").addEventListener("input", applyDSMUserFilter);
$("dsmUserStatusFilter").addEventListener("change", applyDSMUserFilter);
$("dsmGroupSearch").addEventListener("input", applyDSMGroupFilter);
$("departmentSearch").addEventListener("input", applyDepartmentFilter);
$("departmentScopeFilter").addEventListener("change", applyDepartmentFilter);
$("sourceUserSearch").addEventListener("input", applySourceUserFilter);
$("sourceUserScopeFilter").addEventListener("change", applySourceUserFilter);
$("matchSearch").addEventListener("input", applyMatchFilter);
$("matchStatusFilter").addEventListener("change", applyMatchFilter);

function renderProbe(report) {
  $("probeEmpty").classList.add("hidden");
  $("probeResult").classList.remove("hidden");
  $("directoryContextHost").classList.remove("hidden");
  $("metricUsers").textContent = report.user_count;
  $("metricGroups").textContent = report.group_count;
  const availableAPIs = Object.keys(report.api_available || {}).sort();
  const missingAPIs = (report.missing_apis || []).slice().sort();
  const totalAPIs = availableAPIs.length + missingAPIs.length;
  const capabilityPanel = $("capabilityPanel");
  capabilityPanel.dataset.state = missingAPIs.length ? "error" : "success";
  $("capabilitySummary").textContent = missingAPIs.length
    ? `${availableAPIs.length}/${totalAPIs} 可用，${missingAPIs.length} 项异常`
    : `${availableAPIs.length}/${totalAPIs || availableAPIs.length} 正常`;
  $("capabilityRow").innerHTML = [
    ...availableAPIs.map(name => `<span class="available"><b>可用</b>${escapeHTML(name)}</span>`),
    ...missingAPIs.map(name => `<span class="missing"><b>缺失</b>${escapeHTML(name)}</span>`)
  ].join("");
  const users = (report.users || []).map(user => ({ ...user, status: user.expired === "now" ? "disabled" : "enabled", status_label: user.expired === "now" ? "已禁用" : "启用", group_text: (user.groups || []).join("、") }));
  const membersByGroup = {};
  users.forEach(user => (user.groups || []).forEach(group => membersByGroup[group] = (membersByGroup[group] || 0) + 1));
  const groups = (report.groups || []).map(group => ({ ...group, member_count: membersByGroup[group.name] || 0 }));
  upsertGrid("dsmUsers", "dsmUserGrid", users, [
    { title: "DSM 用户名", field: "name", minWidth: 170, formatter: cell => `<strong>${escapeHTML(cell.getValue())}</strong>` },
    { title: "描述", field: "description", minWidth: 180, formatter: emptyFormatter },
    { title: "邮箱", field: "email", minWidth: 210, formatter: emptyFormatter },
    { title: "状态", field: "status_label", width: 105, formatter: cell => `<span class="status-text ${cell.getRow().getData().status}">${escapeHTML(cell.getValue())}</span>` },
    { title: "所属群组", field: "group_text", minWidth: 220, formatter: emptyFormatter }
  ]);
  upsertGrid("dsmGroups", "dsmGroupGrid", groups, [
    { title: "群组名", field: "name", minWidth: 220, formatter: cell => `<strong>${escapeHTML(cell.getValue())}</strong>` },
    { title: "GID", field: "gid", width: 120, formatter: emptyFormatter },
    { title: "描述", field: "description", minWidth: 260, formatter: emptyFormatter },
    { title: "当前成员", field: "member_count", width: 130, hozAlign: "right", sorter: "number" }
  ]);
  applyDSMUserFilter();
  applyDSMGroupFilter();
}

async function loadSystem() {
  state.system = await api("/api/v1/system");
  renderSystemState();
}

function renderSystemState() {
  const data = state.system || {};
  const users = data.users || [];
  $("metricSourceUsers").textContent = users.length;
  $("sourceDepartmentCount").textContent = (data.departments || []).length;
  $("sourceActiveCount").textContent = users.filter(user => user.active).length;
  const managedDepartmentIDs = new Set((data.departments || []).filter(department => department.managed && department.dsm_group).map(department => department.id));
  $("sourceManagedCount").textContent = users.filter(user => user.active && (user.department_ids || []).some(id => managedDepartmentIDs.has(id))).length;
  $("sourceDirectoryAt").textContent = formatDate(data.directory_at) === "—" ? "尚未同步" : formatDate(data.directory_at);
  renderDepartments(data.departments || []);
  renderSourceUsers(users, data.departments || []);
  renderMatches(data.matches || [], users);
  renderPolicy(data.policy || {});
  const runs = data.sync_runs || [];
  renderRuns(runs);
  if (!state.currentRun && runs.length) {
    state.currentRun = runs[0];
    renderSyncRun(state.currentRun);
  }
  renderAudit(data.audit_events || []);
  renderSyncReadiness();
}

function renderDepartments(departments) {
  const users = state.system?.users || [];
  const departmentByID = Object.fromEntries(departments.map(department => [department.id, department]));
  const rows = departments.map(department => {
    const members = users.filter(user => (user.department_ids || []).includes(department.id));
    const leaders = users.filter(user => (user.leader_department_ids || []).includes(department.id)).map(user => user.name);
    return {
      ...department,
      parent_name: departmentByID[department.parent_id]?.name || department.parent_id || "",
      member_count: members.length,
      active_count: members.filter(user => user.active).length,
      leader_names: leaders.join("、"),
      scope: department.managed ? "managed" : "unmanaged",
      proposed_group: department.dsm_group || suggestedGroupName(department.id)
    };
  });
  upsertGrid("departments", "departmentGrid", rows, [
    { title: "部门", field: "name", minWidth: 190, formatter: cell => `<strong>${escapeHTML(cell.getValue())}</strong><small class="cell-subline">${escapeHTML(cell.getRow().getData().id)}</small>` },
    { title: "上级部门", field: "parent_name", minWidth: 150, responsive: 5, formatter: emptyFormatter },
    { title: "成员", field: "active_count", width: 90, responsive: 3, hozAlign: "right", formatter: cell => `${cell.getValue()}<small class="cell-inline-muted"> / ${cell.getRow().getData().member_count}</small>` },
    { title: "部门负责人", field: "leader_names", minWidth: 150, responsive: 4, formatter: emptyFormatter },
    { title: "DSM 群组", field: "proposed_group", minWidth: 210, responsive: 1, formatter: cell => `<input class="group-map-input" data-id="${escapeHTML(cell.getRow().getData().id)}" value="${escapeHTML(cell.getValue())}" aria-label="${escapeHTML(cell.getRow().getData().name)} DSM 群组">` },
    { title: "范围", field: "scope", width: 100, responsive: 2, formatter: cell => cell.getValue() === "managed" ? `<span class="scope-badge managed">已启用</span>` : `<span class="scope-badge">未启用</span>` },
    { title: "操作", field: "id", width: 190, responsive: 1, headerSort: false, formatter: cell => {
      const department = cell.getRow().getData();
      return department.managed
        ? `<div class="grid-actions"><button class="secondary-button save-department" data-id="${escapeHTML(department.id)}" type="button">保存</button><button class="text-button stop-department" data-id="${escapeHTML(department.id)}" type="button">停止同步</button></div>`
        : `<button class="secondary-button enable-department" data-id="${escapeHTML(department.id)}" type="button">启用同步</button>`;
    } }
  ]);
  applyDepartmentFilter();
}

$("departmentGrid").addEventListener("click", async event => {
  const button = event.target.closest(".save-department,.enable-department,.stop-department");
  if (!button) return;
  const input = document.querySelector(`.group-map-input[data-id="${CSS.escape(button.dataset.id)}"]`);
  const managed = !button.classList.contains("stop-department");
  try {
    state.system = await api("/api/v1/departments/map", { method: "POST", body: JSON.stringify({ department_id: button.dataset.id, dsm_group: input.value.trim(), managed }) });
    renderSystemState();
    toast(managed ? "部门已纳入同步范围" : "已停止该部门后续自动同步");
  } catch (error) { toast(error.message, true); }
});

function renderSourceUsers(users, departments) {
  const departmentByID = Object.fromEntries(departments.map(department => [department.id, department]));
  const managed = new Set(departments.filter(department => department.managed && department.dsm_group).map(department => department.id));
  const rows = users.map(user => {
    const departmentNames = (user.department_ids || []).map(id => departmentByID[id]?.name || id);
    const leaderNames = (user.leader_department_ids || []).map(id => departmentByID[id]?.name || id);
    const inManagedScope = user.active && (user.department_ids || []).some(id => managed.has(id));
    return { ...user, department_names: departmentNames.join("、"), leader_names: leaderNames.join("、"), scope: !user.active ? "inactive" : inManagedScope ? "managed" : "unmanaged", status_label: user.active ? "在职" : "离职/停用" };
  });
  upsertGrid("sourceUsers", "sourceUserGrid", rows, [
    { title: "员工", field: "name", minWidth: 150, responsive: 1, formatter: cell => `<strong>${escapeHTML(cell.getValue())}</strong>` },
    { title: "工号 / 用户 ID", field: "employee_no", minWidth: 160, responsive: 2, formatter: cell => escapeHTML(cell.getValue() || cell.getRow().getData().user_id || "—") },
    { title: "邮箱", field: "email", minWidth: 210, responsive: 6, formatter: emptyFormatter },
    { title: "所属部门", field: "department_names", minWidth: 200, responsive: 1, formatter: emptyFormatter },
    { title: "负责部门", field: "leader_names", minWidth: 150, responsive: 5, formatter: emptyFormatter },
    { title: "状态", field: "status_label", width: 115, responsive: 3 },
    { title: "DSM 同步", field: "scope", width: 120, responsive: 1, formatter: cell => cell.getValue() === "managed" ? `<span class="scope-badge managed">纳入范围</span>` : cell.getValue() === "inactive" ? `<span class="scope-badge inactive">人员变动</span>` : `<span class="scope-badge">不同步</span>` }
  ]);
  applySourceUserFilter();
}

$("refreshIdentityDirectory").addEventListener("click", async () => {
	toast("正在拉取当前身份源部门和员工…");
  try {
	state.system = await api("/api/v1/identity/directory", { method: "POST", body: "{}" });
    renderSystemState();
    toast(`通讯录已更新：${state.system.users.length} 人`);
  } catch (error) { toast(error.message, true); }
});

$("importDirectory").addEventListener("click", async () => {
  try {
    const payload = JSON.parse($("directoryJSON").value);
    state.system = await api("/api/v1/directory/import", { method: "POST", body: JSON.stringify(payload) });
    renderSystemState();
    toast("通讯录快照已导入");
  } catch (error) { toast(error.message, true); }
});

$("recalculateMatches").addEventListener("click", async () => {
  toast("正在读取 DSM 并重新计算匹配…");
  try {
    state.system = await api("/api/v1/matches/recalculate", { method: "POST", body: "{}" });
    renderSystemState();
    toast("账号匹配计算完成");
  } catch (error) { toast(error.message, true); }
});

function renderMatches(matches, users) {
  const sourceBySubject = Object.fromEntries(users.map(user => [user.subject, user]));
  const rows = matches.map(match => {
    const user = sourceBySubject[match.subject] || { name: match.subject };
    return { ...match, source_name: user.name, source_identity: user.employee_no || user.email || match.subject, reason_text: (match.reasons || []).join("；") || "无高信匹配" };
  });
  upsertGrid("matches", "matchGrid", rows, [
    { title: "身份源员工", field: "source_name", minWidth: 180, responsive: 1, formatter: cell => `<strong>${escapeHTML(cell.getValue())}</strong><small class="cell-subline">${escapeHTML(cell.getRow().getData().source_identity)}</small>` },
    { title: "DSM 候选账号", field: "dsm_username", minWidth: 210, responsive: 1, formatter: cell => `<input class="match-username" data-subject="${escapeHTML(cell.getRow().getData().subject)}" value="${escapeHTML(cell.getValue() || "")}" placeholder="DSM 用户名" aria-label="${escapeHTML(cell.getRow().getData().source_name)} DSM 候选账号">` },
    { title: "分数", field: "score", width: 85, hozAlign: "right", sorter: "number", responsive: 3 },
    { title: "状态", field: "status", width: 110, responsive: 2, formatter: cell => `<span class="match-badge ${escapeHTML(cell.getValue())}">${escapeHTML(cell.getValue())}</span>` },
    { title: "匹配依据", field: "reason_text", minWidth: 240, responsive: 4, formatter: emptyFormatter },
    { title: "操作", field: "subject", width: 100, responsive: 1, headerSort: false, formatter: cell => `<button class="secondary-button confirm-match" data-subject="${escapeHTML(cell.getValue())}" type="button">确认</button>` }
  ]);
  applyMatchFilter();
}

$("matchGrid").addEventListener("click", async event => {
  const button = event.target.closest(".confirm-match");
  if (!button) return;
  const input = document.querySelector(`.match-username[data-subject="${CSS.escape(button.dataset.subject)}"]`);
  try {
    state.system = await api("/api/v1/matches/confirm", { method: "POST", body: JSON.stringify({ subject: button.dataset.subject, dsm_username: input.value.trim() }) });
    renderSystemState();
    await loadSettings();
    toast("账号绑定已确认，正在生成同步计划…");
    await generateSyncPlan(true);
  } catch (error) { toast(error.message, true); }
});

function renderBindings(bindings) {
  $("metricBindings").textContent = $("bindingCount").textContent = bindings.length;
	$("bindingRows").innerHTML = bindings.length ? bindings.map(binding => `<div class="binding-row"><div><strong>${escapeHTML(binding.dsm_username)}</strong><br><span>${escapeHTML(binding.display_name || binding.email || "已确认账号")}</span></div><span>${escapeHTML(binding.source_type || "dingtalk")} · ${escapeHTML(binding.source_subject || binding.dingtalk_subject)}</span><time>${new Date(binding.confirmed_at).toLocaleDateString()}</time></div>`).join("") : `<div class="empty-state"><p>尚无账号绑定</p></div>`;
}

$("saveBinding").addEventListener("click", async () => {
	const payload = { source_type: $("identitySource").value, source_subject: $("bindingSubject").value.trim(), dsm_username: $("bindingUsername").value.trim(), display_name: $("bindingName").value.trim(), email: $("bindingEmail").value.trim() };
  try {
    const bindings = await api("/api/v1/bindings", { method: "POST", body: JSON.stringify(payload) });
    renderBindings(bindings);
    await loadSystem();
    toast("身份绑定已确认，正在生成同步计划…");
    await generateSyncPlan(true);
  } catch (error) { toast(error.message, true); }
});

function renderPolicy(policy) {
  $("usernameRule").value = policy.username_rule || "employee_no";
  $("usernamePrefix").value = policy.username_prefix || "";
  $("autoBindScore").value = policy.auto_bind_score || 100;
  $("randomPasswordLength").value = policy.random_password_length || 24;
  $("createMissing").checked = Boolean(policy.create_missing);
  $("disableDeparted").checked = Boolean(policy.disable_departed);
  $("removeOldGroups").checked = Boolean(policy.remove_old_groups);
	$("autoApplyEvents").checked = Boolean(policy.auto_apply_events);
  $("scheduleEnabled").checked = Boolean(policy.schedule_enabled);
  $("scheduleInterval").value = policy.schedule_interval_minutes || 1440;
}

function policyPayload() {
	return { username_rule: $("usernameRule").value, username_prefix: $("usernamePrefix").value.trim(), auto_bind_score: Number($("autoBindScore").value), create_missing: $("createMissing").checked, disable_departed: $("disableDeparted").checked, remove_old_groups: $("removeOldGroups").checked, auto_apply_events: $("autoApplyEvents").checked, random_password_length: Number($("randomPasswordLength").value), schedule_enabled: $("scheduleEnabled").checked, schedule_interval_minutes: Number($("scheduleInterval").value) };
}

$("savePolicy").addEventListener("click", async () => {
  try {
    state.system = await api("/api/v1/policy", { method: "PUT", body: JSON.stringify(policyPayload()) });
    renderSystemState();
    toast("同步策略已保存");
  } catch (error) { toast(error.message, true); }
});

async function generateSyncPlan(navigate = false) {
  if (navigate) activatePage("sync");
  toast("正在计算 DSM 差异，不会写入…");
  try {
    state.currentRun = await api("/api/v1/sync/preview", { method: "POST", body: "{}" });
    renderSyncRun(state.currentRun);
    await loadSystem();
    toast(state.currentRun.summary);
    return state.currentRun;
  } catch (error) {
    toast(error.message, true);
    throw error;
  }
}

$("previewSync").addEventListener("click", () => generateSyncPlan(false).catch(() => {}));

function renderSyncReadiness() {
  const data = state.system || {};
  const departments = data.departments || [];
  const users = data.users || [];
  const matches = data.matches || [];
  const managedIDs = new Set(departments.filter(item => item.managed && item.dsm_group).map(item => item.id));
  const scopedUsers = users.filter(user => user.active && (user.department_ids || []).some(id => managedIDs.has(id)));
  const confirmedSubjects = new Set(matches.filter(match => match.confirmed || match.status === "auto").map(match => match.subject));
  const matchedCount = scopedUsers.filter(user => confirmedSubjects.has(user.subject)).length;
  const directoryReady = users.length > 0;
  const scopeReady = managedIDs.size > 0;
  const matchReady = scopedUsers.length > 0 && matchedCount === scopedUsers.length;
  const run = state.currentRun;
  const allVerified = Boolean(run && (run.actions || []).every(action => action.verified));
  const noChanges = Boolean(run && run.status === "preview" && (run.actions || []).length === 0);
  const syncDone = run && (run.status === "completed" || run.status === "partial" || noChanges);
  [
    { id: "syncStepDirectory", ready: directoryReady, active: !directoryReady, detail: directoryReady ? `${users.length} 人已读取` : "尚未拉取" },
    { id: "syncStepScope", ready: scopeReady, active: directoryReady && !scopeReady, detail: scopeReady ? `${managedIDs.size} 个部门` : "尚未选择" },
    { id: "syncStepMatch", ready: matchReady, active: scopeReady && !matchReady, detail: scopedUsers.length ? `${matchedCount}/${scopedUsers.length} 已确认` : "等待部门范围" },
    { id: "syncStepApply", ready: Boolean(syncDone && run.failures === 0 && allVerified), active: matchReady && (!syncDone || !allVerified), detail: !run ? "等待计划" : noChanges ? "无需变更" : run.status === "preview" ? `${(run.actions || []).length} 项待确认` : run.status === "completed" && allVerified ? `${run.successes || 0} 项已验证` : run.status === "completed" ? "旧记录未复核" : run.status === "partial" ? `${run.failures || 0} 项未生效` : "执行中" }
  ].forEach(step => {
    const element = $(step.id);
    if (!element) return;
    element.dataset.state = step.ready ? "ready" : step.active ? "active" : "waiting";
    element.querySelector("small").textContent = step.detail;
  });
  const next = !directoryReady ? { target: "organization", text: "先拉取企业通讯录" }
    : !scopeReady ? { target: "organization", text: "选择需要同步的部门" }
    : !matchReady ? { target: "identity", text: `确认账号匹配（还差 ${Math.max(0, scopedUsers.length - matchedCount)} 人）` }
    : { target: "", text: "准备完成，可以生成同步计划" };
  const readiness = $("syncReadiness");
  if (readiness) readiness.innerHTML = `<strong>${escapeHTML(next.text)}</strong>${next.target ? `<button class="text-button" data-target="${escapeHTML(next.target)}" type="button">去处理</button>` : `<span>系统只会写入预览中列出的动作</span>`}`;
  if ($("previewSync")) $("previewSync").disabled = !matchReady;
  if ($("previewSyncInline")) $("previewSyncInline").disabled = !matchReady;
}

$("syncReadiness").addEventListener("click", event => {
  const button = event.target.closest("button[data-target]");
  if (button) activatePage(button.dataset.target);
});

function renderSyncRun(run) {
  $("syncEmpty").classList.add("hidden");
  $("syncResult").classList.remove("hidden");
  $("syncSummary").textContent = run.summary;
  const finished = run.status === "completed" || run.status === "partial" || run.status === "failed";
  const allVerified = (run.actions || []).every(action => action.verified);
  const noChanges = run.status === "preview" && (run.actions || []).length === 0;
  $("syncResultState").textContent = noChanges ? "DSM 已一致，无需执行" : run.status === "preview" ? "待管理员确认" : run.status === "completed" && allVerified ? "DSM 复核通过" : run.status === "completed" ? "旧版本记录（未自动复核）" : run.status === "partial" ? "部分动作未生效" : statusLabel(run.status);
  $("syncResultState").dataset.state = noChanges ? "completed" : run.status;
  $("syncResult").dataset.state = noChanges ? "aligned" : run.status;
  $("applySync").classList.toggle("hidden", run.status !== "preview" || !(run.actions || []).length);
  $("viewDSMResult").classList.toggle("hidden", !finished);
  $("syncActionRows").innerHTML = (run.actions || []).length ? run.actions.map(action => `<tr><td>${escapeHTML(actionLabel(action.type))}</td><td><strong>${escapeHTML(action.dsm_username)}</strong></td><td>${escapeHTML(action.reason)}</td><td><span class="risk-badge ${escapeHTML(action.risk)}">${escapeHTML(riskLabel(action.risk))}</span></td><td><small>+ ${escapeHTML((action.join_groups || []).join(", ") || "—")}<br>- ${escapeHTML((action.leave_groups || []).join(", ") || "—")}</small></td><td>${action.verified ? `<span class="verification verified">已验证</span><small>${escapeHTML(action.verification || "DSM 目标状态一致")}</small>` : action.execution_error ? `<span class="verification failed">未生效</span><small>${escapeHTML(action.execution_error)}</small>` : action.executed ? `<span class="verification pending">待复核</span>` : `<span class="verification pending">待执行</span>`}</td></tr>`).join("") : `<tr><td colspan="6">DSM 已与当前同步范围一致，无需修改</td></tr>`;
  renderSyncReadiness();
}

function riskLabel(value) { return ({ low: "低风险", medium: "中风险", high: "高风险" })[value] || value; }
function statusLabel(value) { return ({ preview: "待确认", running: "执行中", completed: "已验证", partial: "部分完成", failed: "失败", "scheduled-preview": "定时待确认" })[value] || value; }

function actionLabel(kind) {
  return ({ create_group: "创建群组", create_user: "创建账号", enable_user: "启用账号", disable_user: "禁用账号", set_groups: "调整群组" })[kind] || kind;
}

$("applySync").addEventListener("click", () => {
  $("syncConfirmationText").value = "";
  $("syncConfirmDialog").showModal();
});

$("confirmSyncApply").addEventListener("click", async event => {
  event.preventDefault();
  if (!state.currentRun) return;
  try {
    state.currentRun = await api(`/api/v1/sync/${encodeURIComponent(state.currentRun.id)}/apply`, { method: "POST", body: JSON.stringify({ confirmation: $("syncConfirmationText").value }) });
    $("syncConfirmDialog").close();
    renderSyncRun(state.currentRun);
    await loadSystem();
    try { await probe({ silent: true }); } catch {}
    renderSyncRun(state.currentRun);
    toast(state.currentRun.summary, state.currentRun.failures > 0);
  } catch (error) { toast(error.message, true); }
});

$("viewDSMResult").addEventListener("click", () => {
  const username = (state.currentRun?.actions || []).find(action => action.dsm_username && action.type !== "create_group")?.dsm_username || "";
  activatePage("directory");
  $("directoryTabAccounts").click();
  $("dsmUserSearch").value = username;
  applyDSMUserFilter();
});

function renderRuns(runs) {
  $("syncRunRows").innerHTML = runs.length ? runs.slice(0, 10).map(run => `<div class="run-row"><span>${formatDate(run.created_at)}</span><strong>${escapeHTML(statusLabel(run.status))} · ${(run.actions || []).length} 项</strong><small>${escapeHTML(run.summary || "—")}</small>${run.status === "partial" || run.status === "failed" ? `<button class="secondary-button retry-run" data-id="${escapeHTML(run.id)}" type="button">重试未生效项</button>` : ""}</div>`).join("") : `<p>尚无同步记录</p>`;
}

$("syncRunRows").addEventListener("click", async event => {
  const button = event.target.closest(".retry-run");
  if (!button) return;
  try {
    state.currentRun = await api(`/api/v1/sync/${encodeURIComponent(button.dataset.id)}/retry`, { method: "POST", body: "{}" });
    renderSyncRun(state.currentRun);
    await loadSystem();
    toast(state.currentRun.summary);
  } catch (error) { toast(error.message, true); }
});

async function loadLicense() {
  state.license = await api("/api/v1/license");
  renderLicense();
}

function renderLicense() {
  const value = state.license || {};
  $("licenseMode").textContent = String(value.mode || "unknown").toUpperCase();
  $("licenseEdition").textContent = value.edition || "未授权";
  $("licenseReason").textContent = value.valid ? (value.customer || "License 有效") : (value.reason || "License 无效");
  $("licenseDevice").textContent = value.device_id || "—";
  $("licenseUsers").textContent = value.max_users || "—";
  $("licenseExpiry").textContent = formatDate(value.expires_at);
}

$("installLicense").addEventListener("click", async () => {
  try {
    const payload = JSON.parse($("licenseJSON").value);
    state.license = await api("/api/v1/license", { method: "POST", body: JSON.stringify(payload) });
    renderLicense();
    await loadSystem();
    toast("License 验签成功并已激活");
  } catch (error) { toast(error.message, true); }
});

$("activateOnline").addEventListener("click", async () => {
	try {
		state.settings = await api("/api/v1/settings", { method: "PUT", body: JSON.stringify(settingsPayload()) });
		state.license = await api("/api/v1/license/activate", { method: "POST", body: "{}" });
		renderLicense();
		$("activationCode").value = "";
		toast("授权中心在线激活成功");
	} catch (error) { toast(error.message, true); }
});

function renderSourceLabels(sourceType) {
	const label = sourceType === "wecom" ? "企业微信" : "钉钉";
	$("sourceMetricLabel").textContent = `${label}用户`;
	$("flowSourceLabel").textContent = `${label}认证`;
}

function renderSourcePanels(sourceType) {
	const current = sourceType === "wecom" ? "wecom" : "dingtalk";
	const isWeCom = current === "wecom";
	$("identitySource").value = current;
	$("dingtalkConfigPanel").classList.toggle("hidden", isWeCom);
	$("wecomConfigPanel").classList.toggle("hidden", !isWeCom);
	$("sourceTabDingTalk").setAttribute("aria-pressed", String(!isWeCom));
	$("sourceTabWeCom").setAttribute("aria-pressed", String(isWeCom));
	renderSourceLabels(current);
}

document.querySelectorAll(".source-tabs button").forEach(button => button.addEventListener("click", () => {
	renderSourcePanels(button.dataset.source);
}));

$("identitySource").addEventListener("change", event => renderSourcePanels(event.target.value));

function renderDSMSection(section) {
	const showOIDC = section === "oidc";
	$("dsmConnectionFields").classList.toggle("hidden", showOIDC);
	$("dsmOIDCFields").classList.toggle("hidden", !showOIDC);
	$("dsmTabConnection").setAttribute("aria-pressed", String(!showOIDC));
	$("dsmTabOIDC").setAttribute("aria-pressed", String(showOIDC));
}

$("dsmTabConnection").addEventListener("click", () => renderDSMSection("connection"));
$("dsmTabOIDC").addEventListener("click", () => renderDSMSection("oidc"));

function setupTabs(items) {
	const activate = (item, moveFocus = false) => {
		items.forEach(candidate => {
			const selected = candidate.tab === item.tab;
			$(candidate.tab).setAttribute("aria-selected", String(selected));
			$(candidate.tab).setAttribute("tabindex", selected ? "0" : "-1");
			$(candidate.view).classList.toggle("hidden", !selected);
			if (candidate.context) $(candidate.context).classList.toggle("hidden", !selected);
		});
		redrawVisibleGrids();
		if (moveFocus) $(item.tab).focus({ preventScroll: true });
	};
	items.forEach((item, index) => {
		const tab = $(item.tab);
		tab.setAttribute("aria-controls", item.view);
		$(item.view).setAttribute("role", "tabpanel");
		$(item.view).setAttribute("aria-labelledby", item.tab);
		tab.addEventListener("click", () => activate(item));
		tab.addEventListener("keydown", event => {
			let next = index;
			if (event.key === "ArrowRight") next = (index + 1) % items.length;
			else if (event.key === "ArrowLeft") next = (index - 1 + items.length) % items.length;
			else if (event.key === "Home") next = 0;
			else if (event.key === "End") next = items.length - 1;
			else return;
			event.preventDefault();
			activate(items[next], true);
		});
	});
	activate(items.find(item => $(item.tab).getAttribute("aria-selected") === "true") || items[0]);
}

setupTabs([
	{ tab: "dingTabCredentials", view: "dingCredentialsView" },
	{ tab: "dingTabPermissions", view: "dingPermissionsView" },
	{ tab: "dingTabGuide", view: "dingGuideView" }
]);
setupTabs([
	{ tab: "wecomTabCredentials", view: "wecomCredentialsView" },
	{ tab: "wecomTabAccess", view: "wecomAccessView" },
	{ tab: "wecomTabCallback", view: "wecomCallbackView" }
]);
setupTabs([
	{ tab: "directoryTabAccounts", view: "directoryAccountsView", context: "directoryAccountTools" },
	{ tab: "directoryTabGroups", view: "directoryGroupsView", context: "directoryGroupTools" },
	{ tab: "directoryTabUAT", view: "directoryUATView" }
]);
setupTabs([
	{ tab: "organizationTabMapping", view: "organizationMappingView", context: "organizationMappingTools" },
	{ tab: "organizationTabUsers", view: "organizationUsersView" },
	{ tab: "organizationTabImport", view: "organizationImportView" }
]);
setupTabs([
	{ tab: "identityTabMatches", view: "identityMatchesView", context: "identityMatchTools" },
	{ tab: "identityTabBindings", view: "identityBindingsView" }
]);
setupTabs([
	{ tab: "syncTabPreview", view: "syncPreviewView" },
	{ tab: "syncTabPolicy", view: "syncPolicyView" },
	{ tab: "syncTabHistory", view: "syncHistoryView" }
]);
setupTabs([
	{ tab: "systemTabStatus", view: "systemStatusView" },
	{ tab: "systemTabActivate", view: "systemActivateView" },
	{ tab: "systemTabAudit", view: "systemAuditView" }
]);
setupTabs([
	{ tab: "activationTabOnline", view: "activationOnlineView" },
	{ tab: "activationTabOffline", view: "activationOfflineView" }
]);

$("goConnections").addEventListener("click", () => activatePage("connections"));
$("previewSyncInline").addEventListener("click", () => generateSyncPlan(false).catch(() => {}));
$("testWeComIdentity").addEventListener("click", () => $("testIdentity").click());

function labelResponsiveTables() {
	document.querySelectorAll("table").forEach(table => {
		const labels = Array.from(table.querySelectorAll("thead th"), cell => cell.textContent.trim());
		table.querySelectorAll("tbody tr").forEach(row => {
			Array.from(row.children).forEach((cell, index) => {
				if (cell.colSpan > 1) return;
				cell.dataset.label = labels[index] || "";
			});
		});
	});
}

const responsiveTableObserver = new MutationObserver(labelResponsiveTables);
document.querySelectorAll("tbody").forEach(body => responsiveTableObserver.observe(body, { childList: true }));
labelResponsiveTables();

function renderAudit(events) {
  $("auditCount").textContent = events.length;
  $("auditRows").innerHTML = events.length ? events.slice(0, 30).map(event => `<div class="audit-row"><span>${formatDate(event.at)}</span><strong>${escapeHTML(event.action)}<br><small>${escapeHTML(event.target || "—")}</small></strong><b>${event.success ? "OK" : "FAIL"}</b></div>`).join("") : `<p>尚无审计日志</p>`;
}

function createPayload(apply = false, confirmation = "") {
  return { action: "create_user", apply, confirmation, user: { name: $("testUsername").value.trim(), password: $("testPassword").value, description: $("testDescription").value.trim(), email: $("testEmail").value.trim() } };
}

$("previewCreate").addEventListener("click", async () => {
  try {
    const result = await api("/api/v1/dsm/mutate", { method: "POST", body: JSON.stringify(createPayload()) });
    toast(`${result.message} 目标：${result.target}`);
  } catch (error) { toast(error.message, true); }
});

$("applyCreate").addEventListener("click", () => {
  $("confirmationText").value = "";
  $("confirmDialog").showModal();
});

$("confirmApply").addEventListener("click", async event => {
  event.preventDefault();
  try {
    const result = await api("/api/v1/dsm/mutate", { method: "POST", body: JSON.stringify(createPayload(true, $("confirmationText").value)) });
    $("confirmDialog").close();
    toast(result.message);
    await probe();
  } catch (error) { toast(error.message, true); }
});

boot();
