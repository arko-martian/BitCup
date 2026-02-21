const statusEl = document.getElementById("status");
const repoPathEl = document.getElementById("repoPath");
const headValueEl = document.getElementById("headValue");
const verifyValueEl = document.getElementById("verifyValue");
const refsValueEl = document.getElementById("refsValue");
const objectValueEl = document.getElementById("objectValue");
const oidInputEl = document.getElementById("oidInput");

const openBtn = document.getElementById("openBtn");
const showBtn = document.getElementById("showBtn");

let activeRepoPath = "";

async function tauriInvoke(command, args = {}) {
  if (!window.__TAURI_INTERNALS__) {
    throw new Error("Tauri runtime unavailable.");
  }
  return window.__TAURI_INTERNALS__.invoke(command, args);
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

async function refreshRepoView() {
  if (!activeRepoPath) {
    return;
  }

  headValueEl.textContent = "Loading...";
  verifyValueEl.textContent = "Loading...";
  refsValueEl.textContent = "Loading...";

  const [head, verify, refs] = await Promise.all([
    tauriInvoke("ui_head", { repoPath: activeRepoPath }),
    tauriInvoke("ui_verify_read_only", { repoPath: activeRepoPath }),
    tauriInvoke("ui_list_refs", { repoPath: activeRepoPath }),
  ]);

  headValueEl.textContent = head;
  verifyValueEl.textContent = pretty(verify);
  refsValueEl.textContent = pretty(refs);
}

openBtn.addEventListener("click", async () => {
  const repoPath = repoPathEl.value.trim();
  if (!repoPath) {
    statusEl.textContent = "Enter a repository path.";
    return;
  }

  activeRepoPath = repoPath;
  statusEl.textContent = `Opening ${repoPath}...`;
  objectValueEl.textContent = "-";

  try {
    await refreshRepoView();
    statusEl.textContent = `Opened ${repoPath}.`;
  } catch (err) {
    statusEl.textContent = `Failed to open: ${String(err)}`;
    headValueEl.textContent = "-";
    verifyValueEl.textContent = "-";
    refsValueEl.textContent = "-";
  }
});

showBtn.addEventListener("click", async () => {
  const oid = oidInputEl.value.trim();
  if (!activeRepoPath) {
    statusEl.textContent = "Open a repository first.";
    return;
  }
  if (!oid) {
    statusEl.textContent = "Enter an object id.";
    return;
  }

  objectValueEl.textContent = "Loading...";
  try {
    const value = await tauriInvoke("ui_show_object", {
      repoPath: activeRepoPath,
      oid,
    });
    objectValueEl.textContent = pretty(value);
  } catch (err) {
    objectValueEl.textContent = `Error: ${String(err)}`;
  }
});
