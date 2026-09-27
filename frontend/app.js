const TOKEN_KEY = "foxwallet_token";
const DISCREET_KEY = "ton618_discreet";

const authPanel = document.getElementById("auth-panel");
const appPanel = document.getElementById("app-panel");
const walletsView = document.getElementById("wallets-view");
const accountsView = document.getElementById("accounts-view");
const accountDetailView = document.getElementById("account-detail-view");
const seedView = document.getElementById("seed-view");
const settingsView = document.getElementById("settings-view");
const fingerprintView = document.getElementById("fingerprint-view");
const deleteWalletView = document.getElementById("delete-wallet-view");
const loginForm = document.getElementById("login-form");
const signupForm = document.getElementById("signup-form");
const createWalletForm = document.getElementById("create-wallet-form");
const addAccountForm = document.getElementById("add-account-form");
const sendForm = document.getElementById("send-form");
const revealSeedForm = document.getElementById("reveal-seed-form");
const changeEmailForm = document.getElementById("change-email-form");
const changePasswordForm = document.getElementById("change-password-form");
const deleteWalletForm = document.getElementById("delete-wallet-form");
const networkSelect = document.getElementById("network-select");
const statusEl = document.getElementById("status");
const userEmailEl = document.getElementById("user-email");
const settingsEmailEl = document.getElementById("settings-email");
const walletsList = document.getElementById("wallets-list");
const walletsEmpty = document.getElementById("wallets-empty");
const accountsList = document.getElementById("accounts-list");
const accountsEmpty = document.getElementById("accounts-empty");
const accountsWalletName = document.getElementById("accounts-wallet-name");
const accountsMeta = document.getElementById("accounts-meta");
const accountLimitHint = document.getElementById("account-limit-hint");
const accountsMaxed = document.getElementById("accounts-maxed");
const addAccountBtn = document.getElementById("add-account-btn");
const logoutBtn = document.getElementById("logout-btn");
const discreetBtn = document.getElementById("discreet-btn");
const settingsBtn = document.getElementById("settings-btn");
const backBtn = document.getElementById("back-btn");
const workspaceLabel = document.getElementById("workspace-label");
const portfolioPanel = document.getElementById("portfolio-panel");
const portfolioTotals = document.getElementById("portfolio-totals");
const detailAccountName = document.getElementById("detail-account-name");
const detailNetwork = document.getElementById("detail-network");
const detailBalance = document.getElementById("detail-balance");
const detailAddress = document.getElementById("detail-address");
const sendDestination = document.getElementById("send-destination");
const customAddressField = document.getElementById("custom-address-field");
const sendToAddress = document.getElementById("send-to-address");
const sendBtn = document.getElementById("send-btn");
const receivePanel = document.getElementById("receive-panel");
const sendPanel = document.getElementById("send-panel");
const seedWalletLabel = document.getElementById("seed-wallet-label");
const seedWordsPanel = document.getElementById("seed-words-panel");
const seedWordsEl = document.getElementById("seed-words");
const revealSeedBtn = document.getElementById("reveal-seed-btn");
const copySeedBtn = document.getElementById("copy-seed-btn");
const COPY_SEED_LABEL = copySeedBtn.textContent.trim();
const seedPrompt = document.getElementById("seed-prompt");
const seedPromptWallet = document.getElementById("seed-prompt-wallet");
const seedFingerprintCallout = document.getElementById("seed-fingerprint-callout");
const fingerprintStatusEl = document.getElementById("fingerprint-status");
const settingsWalletPasskeys = document.getElementById("settings-wallet-passkeys");
const fingerprintViewCopy = document.getElementById("fingerprint-view-copy");
const fingerprintSupportNote = document.getElementById("fingerprint-support-note");
const registerFingerprintBtn = document.getElementById("register-fingerprint-btn");
const skipFingerprintBtn = document.getElementById("skip-fingerprint-btn");
const deleteWalletLabel = document.getElementById("delete-wallet-label");
const deleteNoFingerprint = document.getElementById("delete-no-fingerprint");
const deleteWalletBtn = document.getElementById("delete-wallet-btn");
const changeEmailBtn = document.getElementById("change-email-btn");
const changePasswordBtn = document.getElementById("change-password-btn");
const signupFingerprintBox = document.getElementById("signup-fingerprint");
const signupFingerprintStatus = document.getElementById("signup-fingerprint-status");
const signupFingerprintNote = document.getElementById("signup-fingerprint-note");
const signupFingerprintBtn = document.getElementById("signup-fingerprint-btn");
const SIGNUP_FINGERPRINT_NOTE = signupFingerprintNote.textContent.trim();
const FINGERPRINT_VIEW_COPY = fingerprintViewCopy.textContent.trim();
const loginMethods = document.getElementById("login-methods");
const loginContinueBtn = document.getElementById("login-continue-btn");
const loginPasswordStep = document.getElementById("login-password-step");
const loginPasswordInput = loginForm.elements.password;
const loginOptionBtns = loginForm.querySelectorAll(".login-option");

let currentUser = null;
let signupFingerprint = null;
let activeWalletId = null;
let activeAccount = null;
let seedWalletId = null;
let seedWalletName = null;
let revealedMnemonic = null;
let copySeedResetTimer = null;
let walletAccounts = [];
let networksLoaded = false;

const navStack = [];
let currentScreen = null;

function setStatus(message, isError = false) {
  statusEl.textContent = message || "";
  statusEl.classList.toggle("error", Boolean(isError && message));
}

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(path, { ...options, headers });
  let data = null;
  const text = await response.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { detail: text };
    }
  }

  if (!response.ok) {
    const detail = data?.detail;
    const message =
      typeof detail === "string"
        ? detail
        : Array.isArray(detail)
          ? detail.map((d) => d.msg || JSON.stringify(d)).join(", ")
          : `Request failed (${response.status})`;
    throw new Error(message);
  }
  return data;
}

function postJson(path, body) {
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
}

function applyDiscreet(enabled) {
  document.body.classList.toggle("discreet", enabled);
  discreetBtn.setAttribute("aria-pressed", String(enabled));
  discreetBtn.title = enabled ? "Show sensitive info" : "Hide sensitive info";
}

/* —— Navigation —— */

function updateBackButton() {
  backBtn.disabled = navStack.length === 0;
}

function historyEntry(screen) {
  if (screen.name !== "seed") return screen;
  const { mnemonic, ...rest } = screen;
  return rest;
}

function playScreenTransition(el, { back = false } = {}) {
  if (!el) return;
  el.classList.remove("screen-enter", "screen-back");
  void el.offsetWidth;
  el.classList.toggle("screen-back", back);
  el.classList.add("screen-enter");
}

document.addEventListener("animationend", (event) => {
  if (event.target.classList?.contains("screen-enter")) {
    event.target.classList.remove("screen-enter", "screen-back");
  }
});

function visibleAppView() {
  return [...appPanel.children].find((el) => el.id && !el.classList.contains("hidden"));
}

async function navigate(screen, { push = true } = {}) {
  if (push && currentScreen) navStack.push(historyEntry(currentScreen));
  currentScreen = screen;
  updateBackButton();
  try {
    // renderScreen swaps views synchronously before awaiting data, so the
    // new view is already visible when the transition starts.
    const rendering = renderScreen(screen);
    playScreenTransition(visibleAppView(), { back: !push });
    await rendering;
  } catch (err) {
    setStatus(err.message, true);
  }
}

function resetNavigation(screen) {
  navStack.length = 0;
  currentScreen = null;
  return navigate(screen);
}

async function goBack() {
  const previous = navStack.pop();
  if (!previous) return;
  setStatus("");
  await navigate(previous, { push: false });
}

async function renderScreen(screen) {
  if (screen.name !== "seed") clearSeedState();

  switch (screen.name) {
    case "wallets":
      showWalletsView();
      await loadWallets();
      break;
    case "accounts":
      activeWalletId = screen.walletId;
      showAccountsView();
      addAccountForm.reset();
      await loadNetworks();
      await loadAccounts();
      break;
    case "detail":
      activeWalletId = screen.walletId;
      renderAccountDetail(screen.account);
      break;
    case "seed":
      showSeedView(screen.walletId, screen.walletName, {
        mnemonic: screen.mnemonic,
        hasFingerprint: screen.hasFingerprint,
      });
      break;
    case "settings":
      await showSettingsView();
      break;
    case "fingerprint":
      await showFingerprintView(screen);
      break;
    case "delete":
      await showDeleteWalletView(screen);
      break;
    default:
      break;
  }
}

/* —— Views —— */

function showAuth() {
  authPanel.classList.remove("hidden");
  appPanel.classList.add("hidden");
  playScreenTransition(authPanel, { back: true });
  logoutBtn.classList.add("hidden");
  discreetBtn.classList.add("hidden");
  settingsBtn.classList.add("hidden");
  workspaceLabel.textContent = "Account";
  currentUser = null;
  activeWalletId = null;
  activeAccount = null;
  navStack.length = 0;
  currentScreen = null;
  updateBackButton();
  clearSeedState();
  resetSignupFingerprint();
  resetLoginFlow();
}

function showApp() {
  authPanel.classList.add("hidden");
  appPanel.classList.remove("hidden");
  logoutBtn.classList.remove("hidden");
  discreetBtn.classList.remove("hidden");
  settingsBtn.classList.remove("hidden");
  workspaceLabel.textContent = "Vault";
}

function hideAllAppViews() {
  walletsView.classList.add("hidden");
  accountsView.classList.add("hidden");
  accountDetailView.classList.add("hidden");
  seedView.classList.add("hidden");
  settingsView.classList.add("hidden");
  fingerprintView.classList.add("hidden");
  deleteWalletView.classList.add("hidden");
}

function showWalletsView() {
  hideAllAppViews();
  walletsView.classList.remove("hidden");
  activeWalletId = null;
  activeAccount = null;
  workspaceLabel.textContent = "Vault";
}

function showAccountsView() {
  hideAllAppViews();
  accountsView.classList.remove("hidden");
  activeAccount = null;
  workspaceLabel.textContent = "Accounts";
}

function showAccountDetailView() {
  hideAllAppViews();
  accountDetailView.classList.remove("hidden");
  workspaceLabel.textContent = "Send / Receive";
}

function resetCopySeedButton() {
  clearTimeout(copySeedResetTimer);
  copySeedBtn.textContent = COPY_SEED_LABEL;
  copySeedBtn.classList.remove("copied");
}

function showCopiedConfirmation() {
  clearTimeout(copySeedResetTimer);
  copySeedBtn.textContent = "Copied";
  copySeedBtn.classList.add("copied");
  copySeedResetTimer = setTimeout(resetCopySeedButton, 2000);
}

function askToViewSeed(walletName) {
  seedPromptWallet.textContent = walletName;
  seedPrompt.returnValue = "";
  seedPrompt.showModal();
  return new Promise((resolve) => {
    seedPrompt.addEventListener("close", () => resolve(seedPrompt.returnValue === "yes"), {
      once: true,
    });
  });
}

function clearSeedState() {
  resetCopySeedButton();
  seedWalletId = null;
  seedWalletName = null;
  revealedMnemonic = null;
  seedWordsPanel.classList.add("hidden");
  seedWordsEl.innerHTML = "";
  revealSeedForm.reset();
  revealSeedForm.classList.remove("hidden");
  seedFingerprintCallout.classList.add("hidden");
}

function showSeedView(walletId, walletName, options = {}) {
  hideAllAppViews();
  seedView.classList.remove("hidden");
  seedWalletId = walletId;
  seedWalletName = walletName;
  seedWalletLabel.textContent = `Wallet: ${walletName}`;
  workspaceLabel.textContent = "Seed phrase";
  revealedMnemonic = null;
  seedWordsPanel.classList.add("hidden");
  seedWordsEl.innerHTML = "";
  revealSeedForm.reset();

  if (options.mnemonic) {
    revealSeedForm.classList.add("hidden");
    renderSeedWords(options.mnemonic);
    seedFingerprintCallout.classList.toggle("hidden", Boolean(options.hasFingerprint));
  } else {
    revealSeedForm.classList.remove("hidden");
    seedFingerprintCallout.classList.add("hidden");
  }
}

function renderSeedWords(mnemonic) {
  revealedMnemonic = mnemonic;
  const words = mnemonic.trim().split(/\s+/);
  seedWordsEl.innerHTML = words
    .map(
      (word, index) => `
      <li>
        <span class="word-num">${index + 1}</span>
        <span>${escapeHtml(word)}</span>
      </li>
    `,
    )
    .join("");
  seedWordsPanel.classList.remove("hidden");
}

async function showSettingsView() {
  hideAllAppViews();
  settingsView.classList.remove("hidden");
  workspaceLabel.textContent = "Settings";
  settingsEmailEl.textContent = currentUser?.email || "—";
  changeEmailForm.reset();
  changePasswordForm.reset();
  await renderWalletPasskeys();
}

async function renderWalletPasskeys() {
  const wallets = await api("/wallets");
  const linked = wallets.filter((wallet) => wallet.has_fingerprint).length;
  fingerprintStatusEl.textContent = wallets.length
    ? `Linked to ${linked} of ${wallets.length} wallet${wallets.length === 1 ? "" : "s"}`
    : currentUser?.has_fingerprint
      ? "Captured — links to your first wallet"
      : "Not registered";
  fingerprintStatusEl.classList.toggle(
    "registered",
    wallets.length ? linked === wallets.length : Boolean(currentUser?.has_fingerprint),
  );

  settingsWalletPasskeys.innerHTML = "";
  wallets.forEach((wallet) => {
    const row = document.createElement("div");
    row.className = "passkey-row";
    row.innerHTML = `
      <p class="passkey-row-name">${escapeHtml(wallet.name)}</p>
      <div class="passkey-row-actions">
        <span class="fingerprint-status ${wallet.has_fingerprint ? "registered" : ""}">
          ${wallet.has_fingerprint ? "Passkey active" : "No passkey"}
        </span>
        ${wallet.has_fingerprint ? "" : '<button type="button" class="btn ghost-btn">Set up</button>'}
      </div>
    `;
    row.querySelector("button")?.addEventListener("click", () => {
      navigate({ name: "fingerprint", walletId: wallet.id, walletName: wallet.name });
    });
    settingsWalletPasskeys.appendChild(row);
  });
}

async function showFingerprintView(screen) {
  hideAllAppViews();
  fingerprintView.classList.remove("hidden");
  workspaceLabel.textContent = screen.onboarding ? "Onboarding" : "Fingerprint";
  skipFingerprintBtn.textContent = screen.onboarding ? "Skip for now" : "Maybe later";
  fingerprintViewCopy.textContent = screen.walletId
    ? `Register your device's fingerprint sensor (e.g. Touch ID) as the passkey for “${screen.walletName}”. It can be used to log in and, together with your password, protects actions such as deleting this wallet, if you ever choose to.`
    : `${FINGERPRINT_VIEW_COPY} It will be linked to the first wallet you create.`;
  registerFingerprintBtn.disabled = false;

  const reason = await fingerprintUnavailableReason();
  fingerprintSupportNote.classList.toggle("hidden", !reason);
  fingerprintSupportNote.textContent = reason || "";
  registerFingerprintBtn.disabled = Boolean(reason);
}

async function walletHasFingerprint(walletId) {
  const wallets = await api("/wallets");
  return Boolean(wallets.find((wallet) => wallet.id === walletId)?.has_fingerprint);
}

async function showDeleteWalletView(screen) {
  hideAllAppViews();
  deleteWalletView.classList.remove("hidden");
  workspaceLabel.textContent = "Delete wallet";
  activeWalletId = screen.walletId;
  deleteWalletLabel.textContent = `Wallet: ${screen.walletName}`;
  deleteWalletForm.reset();
  deleteWalletBtn.disabled = true;
  const registered = await walletHasFingerprint(screen.walletId);
  deleteNoFingerprint.classList.toggle("hidden", registered);
  deleteWalletBtn.disabled = !registered;
}

/* —— Fingerprint (WebAuthn) —— */

function base64UrlToBuffer(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0)).buffer;
}

function bufferToBase64Url(buffer) {
  let binary = "";
  new Uint8Array(buffer).forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function isIpHost(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":");
}

async function fingerprintUnavailableReason() {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    return "This browser doesn't support fingerprint authentication.";
  }
  if (isIpHost(location.hostname)) {
    const port = location.port ? `:${location.port}` : "";
    return `Browsers only allow fingerprint on named hosts. Open ${location.protocol}//localhost${port} to use it.`;
  }
  try {
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!available) return "No fingerprint sensor (such as Touch ID) is available on this device.";
  } catch {
    return "Could not detect a fingerprint sensor on this device.";
  }
  return null;
}

function webAuthnErrorMessage(err) {
  if (err?.name === "NotAllowedError") return "Fingerprint check was cancelled or timed out.";
  if (err?.name === "InvalidStateError") return "This device's fingerprint is already registered.";
  if (err?.name === "SecurityError") return "Fingerprint is blocked on this address. Open the app via localhost.";
  return err?.message || "Fingerprint check failed.";
}

async function createFingerprintCredential(options) {
  options.challenge = base64UrlToBuffer(options.challenge);
  options.user.id = base64UrlToBuffer(options.user.id);
  (options.excludeCredentials || []).forEach((cred) => {
    cred.id = base64UrlToBuffer(cred.id);
  });

  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey: options });
  } catch (err) {
    throw new Error(webAuthnErrorMessage(err));
  }

  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
      attestationObject: bufferToBase64Url(credential.response.attestationObject),
      transports: credential.response.getTransports?.() || [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment,
  };
}

async function registerFingerprint(walletId = null) {
  const reason = await fingerprintUnavailableReason();
  if (reason) throw new Error(reason);

  const options = await postJson("/webauthn/register/options", { wallet_id: walletId });
  const credential = await createFingerprintCredential(options);
  const user = await postJson("/webauthn/register/verify", { credential, wallet_id: walletId });
  currentUser = { ...currentUser, ...user };
}

function signalRevokedPasskeys(credentialIds) {
  if (typeof PublicKeyCredential?.signalUnknownCredential !== "function") return;
  credentialIds.forEach((credentialId) => {
    PublicKeyCredential.signalUnknownCredential({ rpId: location.hostname, credentialId }).catch(
      () => {},
    );
  });
}

/* —— Login —— */

function loginEmail() {
  return String(loginForm.elements.email.value || "").trim();
}

function selectLoginMethod(method) {
  loginOptionBtns.forEach((btn) => {
    btn.setAttribute("aria-checked", String(btn.dataset.method === method));
  });
  const usePassword = method === "password";
  loginPasswordStep.classList.toggle("hidden", !usePassword);
  loginPasswordInput.disabled = !usePassword;
  if (usePassword) loginPasswordInput.focus();
}

function showLoginMethods() {
  loginContinueBtn.classList.add("hidden");
  loginMethods.classList.remove("hidden");
}

function resetLoginFlow() {
  loginContinueBtn.classList.remove("hidden");
  loginMethods.classList.add("hidden");
  selectLoginMethod(null);
  loginPasswordInput.value = "";
}

async function finishLogin(accessToken) {
  setToken(accessToken);
  resetLoginFlow();
  await loadSession();
}

async function loginWithPassword() {
  const body = new URLSearchParams();
  body.set("username", loginEmail());
  body.set("password", loginPasswordInput.value);
  setStatus("Logging in…");
  const data = await api("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  await finishLogin(data.access_token);
}

async function loginWithFingerprint() {
  const reason = await fingerprintUnavailableReason();
  if (reason) throw new Error(`${reason} Use your password instead.`);

  const email = loginEmail();
  setStatus("Touch your fingerprint sensor…");
  const options = await postJson("/auth/login/fingerprint/options", { email });
  let credential;
  try {
    credential = await verifyFingerprint(options);
  } catch (err) {
    throw new Error(
      `${err.message} If this email has no active wallet passkey on this device, use your password.`,
    );
  }
  setStatus("Verifying fingerprint…");
  const data = await postJson("/auth/login/fingerprint", { email, credential });
  await finishLogin(data.access_token);
}

/* —— Signup fingerprint step —— */

function signupEmail() {
  return String(signupForm.elements.email.value || "").trim();
}

function renderSignupFingerprint({ note } = {}) {
  const registered = Boolean(signupFingerprint);
  signupFingerprintBox.classList.toggle("registered", registered);
  signupFingerprintBox.classList.remove("attention");
  signupFingerprintStatus.classList.toggle("registered", registered);
  signupFingerprintStatus.textContent = registered ? "Registered" : "Not registered";
  signupFingerprintBtn.textContent = registered ? "Re-register" : "Register";
  signupFingerprintNote.textContent = note || SIGNUP_FINGERPRINT_NOTE;
}

function resetSignupFingerprint() {
  signupFingerprint = null;
  renderSignupFingerprint();
}

async function captureSignupFingerprint() {
  if (!signupForm.reportValidity()) return false;

  const reason = await fingerprintUnavailableReason();
  if (reason) {
    renderSignupFingerprint({ note: `${reason} You can register it later in Account settings.` });
    return false;
  }

  const email = signupEmail();
  signupFingerprintBtn.disabled = true;
  try {
    setStatus("Touch your fingerprint sensor…");
    const { signup_id: signupId, options } = await postJson("/auth/signup/fingerprint/options", {
      email,
    });
    const credential = await createFingerprintCredential(options);
    signupFingerprint = { signupId, email, credential };
    renderSignupFingerprint();
    setStatus("Fingerprint captured");
    return true;
  } finally {
    signupFingerprintBtn.disabled = false;
  }
}

async function verifyFingerprint(options) {
  options.challenge = base64UrlToBuffer(options.challenge);
  (options.allowCredentials || []).forEach((cred) => {
    cred.id = base64UrlToBuffer(cred.id);
  });

  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey: options });
  } catch (err) {
    throw new Error(webAuthnErrorMessage(err));
  }

  return {
    id: assertion.id,
    rawId: bufferToBase64Url(assertion.rawId),
    type: assertion.type,
    response: {
      clientDataJSON: bufferToBase64Url(assertion.response.clientDataJSON),
      authenticatorData: bufferToBase64Url(assertion.response.authenticatorData),
      signature: bufferToBase64Url(assertion.response.signature),
      userHandle: assertion.response.userHandle
        ? bufferToBase64Url(assertion.response.userHandle)
        : null,
    },
    clientExtensionResults: assertion.getClientExtensionResults(),
    authenticatorAttachment: assertion.authenticatorAttachment,
  };
}

async function finishFingerprintFlow() {
  if (currentScreen?.onboarding) {
    await resetNavigation({ name: "wallets" });
  } else {
    await goBack();
  }
}

/* —— Data loading —— */

async function loadNetworks() {
  if (networksLoaded) return;
  const networks = await api("/networks");
  networkSelect.innerHTML = '<option value="" disabled selected>Select a network</option>';
  networks.forEach((network) => {
    const option = document.createElement("option");
    option.value = network.id;
    option.textContent = `${network.label} (${network.symbol})`;
    networkSelect.appendChild(option);
  });
  networksLoaded = true;
}

async function loadSession({ onboarding = false } = {}) {
  if (!getToken()) {
    showAuth();
    return;
  }
  try {
    setStatus("Loading…");
    currentUser = await api("/me");
    userEmailEl.textContent = currentUser.email;
    showApp();
    await loadNetworks();
    if (onboarding && !currentUser.has_fingerprint) {
      await resetNavigation({ name: "fingerprint", onboarding: true });
    } else {
      await resetNavigation({ name: "wallets" });
    }
    setStatus("");
  } catch (err) {
    clearToken();
    showAuth();
    setStatus(err.message, true);
  }
}

async function loadWallets() {
  const wallets = await api("/wallets");
  walletsList.innerHTML = "";

  if (!wallets.length) {
    walletsEmpty.classList.remove("hidden");
    return;
  }

  walletsEmpty.classList.add("hidden");
  wallets.forEach((wallet) => {
    const row = document.createElement("div");
    row.className = "list-row";
    row.innerHTML = `
      <div>
        <p class="list-title">${escapeHtml(wallet.name)}</p>
        <p class="list-meta">${wallet.account_count} / ${wallet.max_accounts} accounts</p>
      </div>
      <div class="wallet-actions">
        <button type="button" class="btn ghost-btn open-wallet-btn">Accounts</button>
        <button type="button" class="text-btn seed-btn">Seed phrase</button>
      </div>
    `;
    row.querySelector(".open-wallet-btn").addEventListener("click", () => openWallet(wallet.id));
    row.querySelector(".seed-btn").addEventListener("click", async () => {
      await navigate({ name: "seed", walletId: wallet.id, walletName: wallet.name });
      setStatus("Enter your password to reveal the seed phrase");
    });
    walletsList.appendChild(row);
  });
}

function openWallet(walletId) {
  return navigate({ name: "accounts", walletId });
}

async function loadPortfolio() {
  if (!activeWalletId) return;
  try {
    const data = await api(`/wallets/${activeWalletId}/portfolio`);
    if (!data.totals.length) {
      portfolioPanel.classList.add("hidden");
      return;
    }
    portfolioPanel.classList.remove("hidden");
    portfolioTotals.innerHTML = data.totals
      .map(
        (total) => `
        <div class="portfolio-row">
          <span class="portfolio-amount">${escapeHtml(total.amount)}</span>
          <span class="portfolio-symbol">${escapeHtml(total.symbol)}</span>
        </div>
      `,
      )
      .join("");
  } catch {
    portfolioPanel.classList.add("hidden");
  }
}

async function loadAccounts() {
  if (!activeWalletId) return;
  setStatus("Loading accounts…");
  const data = await api(`/wallets/${activeWalletId}/accounts`);
  walletAccounts = data.accounts;
  accountsWalletName.textContent = data.wallet_name;
  accountsMeta.textContent = `${data.account_count} / ${data.max_accounts} accounts`;
  accountLimitHint.textContent = `You can add up to ${data.max_accounts} accounts in this wallet.`;
  seedWalletName = data.wallet_name;

  accountsList.innerHTML = "";
  if (!data.accounts.length) {
    accountsEmpty.classList.remove("hidden");
    portfolioPanel.classList.add("hidden");
  } else {
    accountsEmpty.classList.add("hidden");
    for (const account of data.accounts) {
      const row = document.createElement("div");
      row.className = "list-row account-row";
      row.innerHTML = `
        <div class="account-info">
          <p class="list-title">${escapeHtml(account.name)}</p>
          <p class="list-meta">${escapeHtml(account.network_label)}</p>
          <p class="list-meta balance-line" data-account-id="${account.id}">Balance: …</p>
        </div>
        <div class="account-actions">
          <button type="button" class="btn ghost-btn open-account-btn">Open</button>
        </div>
      `;
      row.querySelector(".open-account-btn").addEventListener("click", () => {
        openAccount(account);
      });
      accountsList.appendChild(row);
    }
    await Promise.all([
      loadPortfolio(),
      ...data.accounts.map((account) => loadAccountBalance(account.id)),
    ]);
  }

  if (data.can_add_account) {
    addAccountForm.classList.remove("hidden");
    accountsMaxed.classList.add("hidden");
  } else {
    addAccountForm.classList.add("hidden");
    accountsMaxed.classList.remove("hidden");
  }

  setStatus("");
}

async function loadAccountBalance(accountId) {
  const line = accountsList.querySelector(`.balance-line[data-account-id="${accountId}"]`);
  if (!line) return;
  try {
    const balance = await api(`/accounts/${accountId}/balance`);
    line.textContent = `${balance.amount} ${balance.symbol}`;
  } catch {
    line.textContent = "Balance unavailable";
  }
}

function openAccount(account) {
  return navigate({ name: "detail", walletId: activeWalletId, account });
}

function renderAccountDetail(account) {
  activeAccount = account;
  showAccountDetailView();
  detailAccountName.textContent = account.name;
  detailNetwork.textContent = account.network_label;
  detailAddress.textContent = account.address;
  detailBalance.textContent = "…";
  sendForm.reset();
  setTransferMode("receive");
  populateSendDestinations();
  refreshDetailBalance();
}

function populateSendDestinations() {
  if (!activeAccount) return;
  const peers = walletAccounts.filter(
    (a) => a.network === activeAccount.network && a.id !== activeAccount.id,
  );
  sendDestination.innerHTML = '<option value="custom">Any address</option>';
  peers.forEach((peer) => {
    const option = document.createElement("option");
    option.value = peer.id;
    option.textContent = `${peer.name} (${peer.address.slice(0, 6)}…${peer.address.slice(-4)})`;
    sendDestination.appendChild(option);
  });
  updateCustomAddressVisibility();
}

function updateCustomAddressVisibility() {
  const isCustom = sendDestination.value === "custom";
  customAddressField.classList.toggle("hidden", !isCustom);
  sendToAddress.required = isCustom;
}

async function refreshDetailBalance() {
  if (!activeAccount) return;
  detailBalance.textContent = "…";
  try {
    const balance = await api(`/accounts/${activeAccount.id}/balance`);
    detailBalance.textContent = `${balance.amount} ${balance.symbol}`;
  } catch {
    detailBalance.textContent = "Unavailable";
  }
}

function setTransferMode(mode) {
  document.querySelectorAll("[data-transfer]").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.transfer === mode);
  });
  receivePanel.classList.toggle("hidden", mode !== "receive");
  sendPanel.classList.toggle("hidden", mode !== "send");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

/* —— Event wiring —— */

document.querySelectorAll(".mode").forEach((tab) => {
  tab.addEventListener("click", () => {
    if (tab.dataset.tab) {
      document.querySelectorAll(".mode[data-tab]").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      const which = tab.dataset.tab;
      loginForm.classList.toggle("hidden", which !== "login");
      signupForm.classList.toggle("hidden", which !== "signup");
      playScreenTransition(which === "signup" ? signupForm : loginForm, {
        back: which === "login",
      });
    }
  });
});

document.querySelectorAll("[data-transfer]").forEach((tab) => {
  tab.addEventListener("click", () => setTransferMode(tab.dataset.transfer));
});

sendDestination.addEventListener("change", updateCustomAddressVisibility);

backBtn.addEventListener("click", goBack);

settingsBtn.addEventListener("click", () => {
  if (currentScreen?.name === "settings") return;
  navigate({ name: "settings" });
  setStatus("");
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (loginMethods.classList.contains("hidden")) {
    showLoginMethods();
    setStatus("");
    return;
  }
  if (loginPasswordInput.disabled) return;

  try {
    await loginWithPassword();
  } catch (err) {
    setStatus(err.message, true);
  }
});

loginOptionBtns.forEach((btn) => {
  btn.addEventListener("click", async () => {
    const method = btn.dataset.method;
    selectLoginMethod(method);
    setStatus("");
    if (method !== "fingerprint") return;

    loginOptionBtns.forEach((b) => (b.disabled = true));
    try {
      await loginWithFingerprint();
    } catch (err) {
      setStatus(err.message, true);
    } finally {
      loginOptionBtns.forEach((b) => (b.disabled = false));
    }
  });
});

loginForm.elements.email.addEventListener("input", () => {
  if (!loginMethods.classList.contains("hidden")) resetLoginFlow();
});

signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(signupForm);
  try {
    if (!signupFingerprint && !(await fingerprintUnavailableReason())) {
      if (!(await captureSignupFingerprint())) return;
    }

    setStatus("Creating account…");
    const body = { email: form.get("email"), password: form.get("password") };
    if (signupFingerprint) {
      body.fingerprint = {
        signup_id: signupFingerprint.signupId,
        credential: signupFingerprint.credential,
      };
    }
    const data = await postJson("/auth/signup", body);
    resetSignupFingerprint();
    setToken(data.access_token);
    await loadSession({ onboarding: true });
  } catch (err) {
    resetSignupFingerprint();
    signupFingerprintBox.classList.add("attention");
    setStatus(err.message, true);
  }
});

signupFingerprintBtn.addEventListener("click", async () => {
  try {
    resetSignupFingerprint();
    await captureSignupFingerprint();
  } catch (err) {
    resetSignupFingerprint();
    signupFingerprintBox.classList.add("attention");
    setStatus(err.message, true);
  }
});

signupForm.elements.email.addEventListener("input", () => {
  if (signupFingerprint && signupFingerprint.email !== signupEmail()) {
    resetSignupFingerprint();
    setStatus("Email changed — register your fingerprint again.");
  }
});

logoutBtn.addEventListener("click", () => {
  clearToken();
  showAuth();
  setStatus("Logged out");
});

createWalletForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(createWalletForm);
  const name = String(form.get("name") || "").trim();
  if (!name) return;

  try {
    setStatus("Creating wallet…");
    const wallet = await postJson("/wallets", { name });
    createWalletForm.reset();
    await loadWallets();
    if (wallet.mnemonic) {
      setStatus("Wallet created");
      if (await askToViewSeed(wallet.name)) {
        await navigate({
          name: "seed",
          walletId: wallet.id,
          walletName: wallet.name,
          mnemonic: wallet.mnemonic,
          hasFingerprint: wallet.has_fingerprint,
        });
        setStatus("Wallet created — save your seed phrase now");
      } else {
        await openWallet(wallet.id);
        setStatus("Seed phrase skipped — view it anytime from “Seed phrase”");
      }
    } else {
      setStatus("Wallet created");
    }
  } catch (err) {
    setStatus(err.message, true);
  }
});

document.getElementById("view-seed-from-accounts").addEventListener("click", async () => {
  if (!activeWalletId) return;
  await navigate({
    name: "seed",
    walletId: activeWalletId,
    walletName: seedWalletName || accountsWalletName.textContent,
  });
  setStatus("Enter your password to reveal the seed phrase");
});

revealSeedForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!seedWalletId) return;

  const form = new FormData(revealSeedForm);
  revealSeedBtn.disabled = true;
  try {
    setStatus("Unlocking seed phrase…");
    const data = await postJson(`/wallets/${seedWalletId}/seed`, {
      password: form.get("password"),
    });
    revealSeedForm.classList.add("hidden");
    renderSeedWords(data.mnemonic);
    setStatus("Seed phrase unlocked — keep it private");
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    revealSeedBtn.disabled = false;
  }
});

copySeedBtn.addEventListener("click", async () => {
  if (!revealedMnemonic) return;
  try {
    await navigator.clipboard.writeText(revealedMnemonic);
    setStatus("Seed phrase copied");
    showCopiedConfirmation();
  } catch {
    setStatus("Could not copy seed phrase", true);
  }
});

document.getElementById("hide-seed-btn").addEventListener("click", () => {
  resetCopySeedButton();
  revealedMnemonic = null;
  seedWordsPanel.classList.add("hidden");
  seedWordsEl.innerHTML = "";
  revealSeedForm.classList.remove("hidden");
  revealSeedForm.reset();
  setStatus("Seed phrase hidden");
});

document.getElementById("seed-fingerprint-btn").addEventListener("click", () => {
  navigate({ name: "fingerprint", walletId: seedWalletId, walletName: seedWalletName });
});

document.getElementById("copy-address-btn").addEventListener("click", async () => {
  if (!activeAccount) return;
  try {
    await navigator.clipboard.writeText(activeAccount.address);
    setStatus("Address copied — ready to receive");
  } catch {
    setStatus("Could not copy address", true);
  }
});

document.getElementById("refresh-balance-btn").addEventListener("click", async () => {
  setStatus("Refreshing balance…");
  await refreshDetailBalance();
  if (activeWalletId) await loadPortfolio();
  setStatus("Balance updated");
});

addAccountForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!activeWalletId) return;

  const form = new FormData(addAccountForm);
  const name = String(form.get("name") || "").trim();
  const network = String(form.get("network") || "");
  if (!name || !network) {
    setStatus("Account name and network are required", true);
    return;
  }

  addAccountBtn.disabled = true;
  try {
    setStatus("Verifying password and creating account…");
    await postJson(`/wallets/${activeWalletId}/accounts`, {
      name,
      network,
      password: form.get("password"),
    });
    addAccountForm.reset();
    await loadAccounts();
    setStatus(`Account “${name}” added`);
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    addAccountBtn.disabled = false;
  }
});

sendForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!activeAccount) return;

  const form = new FormData(sendForm);
  const amount = String(form.get("amount") || "").trim();
  const password = String(form.get("password") || "");
  const dest = sendDestination.value;

  const body = { amount, password };
  if (dest === "custom") {
    const toAddress = String(form.get("to_address") || "").trim();
    if (!toAddress) {
      setStatus("Destination address is required", true);
      return;
    }
    body.to_address = toAddress;
  } else {
    body.to_address = "";
    body.to_account_id = dest;
  }

  sendBtn.disabled = true;
  try {
    setStatus("Signing and broadcasting…");
    const result = await postJson(`/accounts/${activeAccount.id}/send`, body);
    sendForm.reset();
    updateCustomAddressVisibility();
    await refreshDetailBalance();
    if (activeWalletId) await loadPortfolio();
    setStatus(`Sent ${result.amount} ${result.symbol} · ${result.tx_hash.slice(0, 10)}…`);
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    sendBtn.disabled = false;
  }
});

changeEmailForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(changeEmailForm);
  changeEmailBtn.disabled = true;
  try {
    setStatus("Updating email…");
    const user = await postJson("/me/email", {
      new_email: String(form.get("new_email") || "").trim(),
      password: form.get("password"),
    });
    currentUser = { ...currentUser, ...user };
    userEmailEl.textContent = currentUser.email;
    settingsEmailEl.textContent = currentUser.email;
    changeEmailForm.reset();
    setStatus("Email updated — use it next time you log in");
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    changeEmailBtn.disabled = false;
  }
});

changePasswordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(changePasswordForm);
  const newPassword = String(form.get("new_password") || "");
  if (newPassword !== String(form.get("confirm_password") || "")) {
    setStatus("New passwords don't match", true);
    return;
  }

  changePasswordBtn.disabled = true;
  try {
    setStatus("Updating password…");
    await postJson("/me/password", {
      current_password: form.get("current_password"),
      new_password: newPassword,
    });
    changePasswordForm.reset();
    setStatus("Password updated");
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    changePasswordBtn.disabled = false;
  }
});

registerFingerprintBtn.addEventListener("click", async () => {
  registerFingerprintBtn.disabled = true;
  try {
    setStatus("Touch your fingerprint sensor…");
    await registerFingerprint(currentScreen?.walletId || null);
    await finishFingerprintFlow();
    setStatus("Fingerprint registered");
  } catch (err) {
    setStatus(err.message, true);
    registerFingerprintBtn.disabled = false;
  }
});

skipFingerprintBtn.addEventListener("click", async () => {
  const onboarding = Boolean(currentScreen?.onboarding);
  await finishFingerprintFlow();
  if (onboarding) setStatus("You can register your fingerprint later in Settings");
});

document.getElementById("open-delete-wallet-btn").addEventListener("click", () => {
  if (!activeWalletId) return;
  navigate({
    name: "delete",
    walletId: activeWalletId,
    walletName: seedWalletName || accountsWalletName.textContent,
  });
  setStatus("");
});

document.getElementById("delete-register-fingerprint-btn").addEventListener("click", () => {
  const screen = currentScreen;
  if (screen?.name !== "delete") return;
  navigate({ name: "fingerprint", walletId: screen.walletId, walletName: screen.walletName });
});

deleteWalletForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const screen = currentScreen;
  if (screen?.name !== "delete") return;

  const password = String(new FormData(deleteWalletForm).get("password") || "");
  deleteWalletBtn.disabled = true;
  try {
    const reason = await fingerprintUnavailableReason();
    if (reason) throw new Error(reason);

    setStatus("Checking password…");
    const options = await postJson(`/wallets/${screen.walletId}/delete/options`, { password });

    setStatus("Confirm with your fingerprint…");
    const credential = await verifyFingerprint(options);

    setStatus("Deleting wallet…");
    const result = await postJson(`/wallets/${screen.walletId}/delete`, { password, credential });
    signalRevokedPasskeys(result.revoked_credential_ids || []);
    currentUser = await api("/me");
    await resetNavigation({ name: "wallets" });
    setStatus(`Wallet “${screen.walletName}” deleted and its passkey revoked`);
  } catch (err) {
    setStatus(err.message, true);
    deleteWalletBtn.disabled = false;
  }
});

discreetBtn.addEventListener("click", () => {
  const enabled = !document.body.classList.contains("discreet");
  localStorage.setItem(DISCREET_KEY, enabled ? "1" : "0");
  applyDiscreet(enabled);
  setStatus(enabled ? "Discreet mode on — sensitive info hidden" : "Discreet mode off");
});

applyDiscreet(localStorage.getItem(DISCREET_KEY) === "1");
loadNetworks().catch(() => {});
loadSession();
