const API_BASE = "http://10.10.50.158:8000";

async function fetchJSON(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error("API failed: " + url);
  return await res.json();
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.innerText = value ?? 0;
}

function getRole() {
  return localStorage.getItem("role");
}

function getEmail() {
  return localStorage.getItem("email");
}

function logout() {
  localStorage.clear();
  window.location.href = "index.html";
}

function protectPage(allowedRoles) {
  const role = getRole();

  if (!role || !allowedRoles.includes(role)) {
    alert("Access denied");
    window.location.href = "index.html";
  }
}

function applyRoleVisibility() {
  const role = getRole();

  document.querySelectorAll(".super-admin-only").forEach(el => {
    el.style.display = role === "admin" ? "" : "none";
  });

  document.querySelectorAll(".admin-only").forEach(el => {
    el.style.display = ["admin", "patch_admin"].includes(role) ? "" : "none";
  });

  document.querySelectorAll(".servers-only").forEach(el => {
    el.style.display = ["admin", "patch_admin", "read_only"].includes(role) ? "" : "none";
  });

  document.querySelectorAll(".schedule-only").forEach(el => {
    el.style.display = ["admin", "patch_admin", "read_only"].includes(role) ? "" : "none";
  });
}

function hydrateUserHeader() {
  const roleText = document.getElementById("userRoleText");
  const emailText = document.getElementById("userEmailText");
  if (!roleText && !emailText) return;

  const role = getRole();
  const email = getEmail();

  const labelMap = {
    admin: "Admin",
    patch_admin: "Patch Admin",
    server_owner: "Server Owner",
    read_only: "Read Only"
  };

  if (roleText) roleText.innerText = labelMap[role] || "User";
  if (emailText) emailText.innerText = email || "Not signed in";
}

async function login() {
  const email = document.getElementById("loginEmail").value;
  const status = document.getElementById("loginStatus");

  if (!email) {
    status.innerText = "Enter email";
    return;
  }

  try {
    const data = await fetchJSON(`${API_BASE}/login`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ email })
    });

    if (data.status !== "success") {
      status.innerText = data.message;
      return;
    }

    localStorage.setItem("email", data.email);
    localStorage.setItem("role", data.role);

    if (data.role === "admin") {
      window.location.href = "admin.html";
    } else if (data.role === "patch_admin") {
      window.location.href = "dashboard.html";
    } else if (data.role === "server_owner") {
      window.location.href = `client.html?email=${encodeURIComponent(data.email)}`;
    } else if (data.role === "read_only") {
      window.location.href = "dashboard.html";
    }

  } catch (err) {
    console.error(err);
    status.innerText = "Login failed";
  }
}

async function loadDashboard() {
  try {
    const summary = await fetchJSON(`${API_BASE}/dashboard-summary`);
    const ownerSummary = await fetchJSON(`${API_BASE}/owner-summary`);
    const vulnDetails = await fetchJSON(`${API_BASE}/vulnerability-details`);
    const uploadHistory = await fetchJSON(`${API_BASE}/upload-history`);

    setText("totalRecords", summary.total_records);
    setText("totalServers", summary.total_servers);
    setText("totalOwners", summary.total_owners);
    setText("criticalCount", summary.critical);
    setText("highCount", summary.high);

    const ownerTable = document.getElementById("ownerTable");
    if (ownerTable) {
      ownerTable.innerHTML = "";

      ownerSummary.owners.forEach(owner => {
        ownerTable.innerHTML += `
          <tr>
            <td>${owner.owner}</td>
            <td>${owner.total_servers}</td>
            <td>${owner.total_vulnerabilities}</td>
            <td>${owner.critical}</td>
            <td>${owner.high}</td>
            <td>${owner.medium}</td>
            <td>${owner.low}</td>
          </tr>
        `;
      });
    }

    const vulnerabilityTable = document.getElementById("vulnerabilityTable");
    if (vulnerabilityTable) {
      vulnerabilityTable.innerHTML = "";

      vulnDetails.data.slice(0, 100).forEach(row => {
        vulnerabilityTable.innerHTML += `
          <tr>
            <td>${row.hostname || ""}</td>
            <td>${row["owner email"] || ""}</td>
            <td>${row["cve id"] || ""}</td>
            <td>${row["cvss severity"] || ""}</td>
            <td>${row["days open"] || ""}</td>
            <td>${row["exploit status"] || ""}</td>
          </tr>
        `;
      });
    }

    const uploadHistoryTable = document.getElementById("uploadHistoryTable");
    if (uploadHistoryTable) {
      uploadHistoryTable.innerHTML = "";

      uploadHistory.history.forEach(item => {
        uploadHistoryTable.innerHTML += `
          <tr>
            <td>${item.upload_id}</td>
            <td>${item.upload_date}</td>
            <td>${item.file_name}</td>
            <td>${item.total_records}</td>
            <td>${item.total_servers}</td>
            <td>${item.critical}</td>
            <td>${item.high}</td>
            <td>${item.medium}</td>
            <td>${item.low}</td>
          </tr>
        `;
      });
    }

  } catch (err) {
    console.error(err);
    alert("Failed to load dashboard data");
  }
}

async function loadUploadHistory() {
  const uploadHistoryTable = document.getElementById("uploadHistoryTable");
  if (!uploadHistoryTable) return;

  try {
    const uploadHistory = await fetchJSON(`${API_BASE}/upload-history`);

    uploadHistoryTable.innerHTML = "";
    uploadHistory.history.forEach(item => {
      uploadHistoryTable.innerHTML += `
        <tr>
          <td>${item.upload_id}</td>
          <td>${item.upload_date}</td>
          <td>${item.file_name}</td>
          <td>${item.total_records}</td>
          <td>${item.total_servers}</td>
          <td>${item.critical}</td>
          <td>${item.high}</td>
          <td>${item.medium}</td>
          <td>${item.low}</td>
        </tr>
      `;
    });
  } catch (err) {
    console.error(err);
    alert("Failed to load upload history");
  }
}

async function uploadServerMaster() {
  const file = document.getElementById("serverMasterFile").files[0];
  if (!file) return alert("Select server master file");

  const formData = new FormData();
  formData.append("file", file);

  try {
    const data = await fetchJSON(`${API_BASE}/upload-server-master`, {
      method: "POST",
      body: formData
    });

    document.getElementById("serverUploadStatus").innerText =
      `Uploaded successfully. Servers: ${data.summary.total_servers}, Owners: ${data.summary.unique_owners}`;

  } catch (err) {
    console.error(err);
    alert("Server master upload failed");
  }
}

async function uploadVulnerabilities() {
  const file = document.getElementById("vulnerabilityFile").files[0];
  if (!file) return alert("Select vulnerability file");

  const formData = new FormData();
  formData.append("file", file);

  try {
    const data = await fetchJSON(`${API_BASE}/upload-vulnerabilities`, {
      method: "POST",
      body: formData
    });

    document.getElementById("vulnUploadStatus").innerText =
      `Uploaded successfully. Records: ${data.summary.total_records}, Servers: ${data.summary.total_servers}`;

  } catch (err) {
    console.error(err);
    alert("Vulnerability upload failed");
  }
}

async function triggerMailer() {
  const status = document.getElementById("mailerStatus");

  if (status) status.innerText = "Sending emails...";

  try {
    const data = await fetchJSON(`${API_BASE}/trigger-mailer`, {
      method: "POST"
    });

    if (status) {
      status.innerText = `Emails sent: ${data.emails_sent}`;
    }

    alert(`Emails sent: ${data.emails_sent}`);

  } catch (err) {
    console.error(err);
    if (status) status.innerText = "Failed to send emails";
    alert("Failed to send emails");
  }
}

function getQueryParam(name) {
  const params = new URLSearchParams(window.location.search);
  return params.get(name);
}

async function loadClientDashboard() {
  let email = getQueryParam("email") || getEmail();

  if (!email) {
    alert("No email found");
    return;
  }

  setText("clientEmailLabel", email);

  try {
    const data = await fetchJSON(`${API_BASE}/client-data?email=${encodeURIComponent(email)}`);

    setText("clientTotalServers", data.total_servers);
    setText("clientTotalVulns", data.total_vulnerabilities);

    const rows = data.data || [];
    const severity = rows.map(r => String(r["cvss severity"] || "").toLowerCase());

    setText("clientCritical", severity.filter(s => s === "critical").length);
    setText("clientHigh", severity.filter(s => s === "high").length);

    const table = document.getElementById("clientTable");
    if (table) {
      table.innerHTML = "";

      rows.forEach(row => {
        table.innerHTML += `
          <tr>
            <td>${row.hostname || ""}</td>
            <td>${row["cve id"] || ""}</td>
            <td>${row["cvss severity"] || ""}</td>
            <td>${row["days open"] || ""}</td>
            <td>${row["exploit status"] || ""}</td>
          </tr>
        `;
      });
    }

  } catch (err) {
    console.error(err);
    alert("Failed to load client dashboard");
  }
}

async function loadUsers() {
  const table = document.getElementById("usersTable");
  if (!table) return;

  try {
    const data = await fetchJSON(`${API_BASE}/users`);

    table.innerHTML = "";

    data.users.forEach(user => {
      table.innerHTML += `
        <tr>
          <td>${user.email}</td>
          <td>${user.role}</td>
          <td>${user.status}</td>
          <td>
            <select class="field field-sm" id="role-${user.email}">
              <option value="admin" ${user.role === "admin" ? "selected" : ""}>Admin</option>
              <option value="patch_admin" ${user.role === "patch_admin" ? "selected" : ""}>Patch Admin</option>
              <option value="server_owner" ${user.role === "server_owner" ? "selected" : ""}>Server Owner</option>
              <option value="read_only" ${user.role === "read_only" ? "selected" : ""}>Read Only</option>
            </select>
          </td>
          <td>
            <select class="field field-sm" id="status-${user.email}">
              <option value="active" ${user.status === "active" ? "selected" : ""}>Active</option>
              <option value="inactive" ${user.status === "inactive" ? "selected" : ""}>Inactive</option>
            </select>
          </td>
          <td>
            <button class="btn btn-sm" onclick="updateUser('${user.email}')">Update</button>
            <button class="btn btn-sm danger" onclick="deleteUser('${user.email}')">Delete</button>
          </td>
        </tr>
      `;
    });

  } catch (err) {
    console.error(err);
    alert("Failed to load users");
  }
}

async function addUser() {
  const email = document.getElementById("newUserEmail").value;
  const role = document.getElementById("newUserRole").value;
  const status = document.getElementById("newUserStatus").value;
  const resultText = document.getElementById("userActionStatus");

  try {
    const data = await fetchJSON(`${API_BASE}/add-user`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        admin_role: getRole(),
        email,
        role,
        status
      })
    });

    resultText.innerText = data.message || data.status;
    loadUsers();

  } catch (err) {
    console.error(err);
    resultText.innerText = "Failed to add user";
  }
}

async function updateUser(email) {
  const role = document.getElementById(`role-${email}`).value;
  const status = document.getElementById(`status-${email}`).value;

  await fetchJSON(`${API_BASE}/update-user`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      admin_role: getRole(),
      email,
      role,
      status
    })
  });

  loadUsers();
}

async function deleteUser(email) {
  if (!confirm("Delete user?")) return;

  await fetchJSON(`${API_BASE}/delete-user`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      admin_role: getRole(),
      email
    })
  });

  loadUsers();
}

async function loadServersPage() {
  const table = document.getElementById("serversTable");
  if (!table) return;

  try {
    const data = await fetchJSON(`${API_BASE}/servers`);

    table.innerHTML = "";

    data.servers.forEach(server => {
      table.innerHTML += `
        <tr>
          <td>${server["server name"] || ""}</td>
          <td>${server["owner email"] || ""}</td>
          <td>${server["application name"] || ""}</td>
          <td>${server["pilot server"] || ""}</td>
          <td>${server["maintenance window"] || ""}</td>
        </tr>
      `;
    });

  } catch (err) {
    console.error(err);
    alert("Failed to load servers");
  }
}

async function loadSchedulePage() {
  const data = await fetchJSON(`${API_BASE}/schedule`);

  setText("totalScheduled", data.summary.total_scheduled);
  setText("thisMonthWindows", data.summary.this_month);
  setText("notificationDue", data.summary.notification_due);
  setText("missingWindow", data.summary.missing_window);

  const table = document.getElementById("scheduleTable");
  if (!table) return;

  table.innerHTML = "";

  data.schedule.forEach(item => {
    table.innerHTML += `
      <tr>
        <td>${item.server_name}</td>
        <td>${item.owner_email}</td>
        <td>${item.maintenance_window}</td>
        <td>${item.next_patch_date}</td>
        <td>${item.notification_date}</td>
        <td>${item.status}</td>
      </tr>
    `;
  });
}

window.addEventListener("DOMContentLoaded", () => {
  applyRoleVisibility();
  hydrateUserHeader();

  const page = window.location.pathname;

  if (page.includes("admin.html")) {
    protectPage(["admin"]);
    loadUsers();
  }

  if (page.includes("upload.html")) {
    protectPage(["admin", "patch_admin"]);
    loadUploadHistory();
  }

  if (page.includes("dashboard.html")) {
    protectPage(["admin", "patch_admin", "read_only"]);
    loadDashboard();
  }

  if (page.includes("client.html")) {
    protectPage(["server_owner"]);
    loadClientDashboard();
  }

  if (page.includes("servers.html")) {
    protectPage(["admin", "patch_admin", "read_only"]);
    loadServersPage();
  }

  if (page.includes("schedule.html")) {
    protectPage(["admin", "patch_admin", "read_only"]);
    loadSchedulePage();
  }
});
