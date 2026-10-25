/* ============================================================
   SecureVault — app.js
   Handles: Auth + 2FA OTP, Drag-Drop Upload, Folder Management,
            Document Preview, Chart.js Stats, Download Counter
   ============================================================ */

let savedDocuments = [];
let savedFolders = [];
let isLoginMode = false;
let pendingKycMobile = "";
let currentTab = "dashboard";
let activeFolderId = null;  // null = show all docs
let uploadChart = null;     // Chart.js instance

// ─── INIT ────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    checkAuthSession();
    initDragDrop();
});

// ─── AUTH ────────────────────────────────────────────────────
async function checkAuthSession() {
    const res = await fetch('/api/auth/status');
    const data = await res.json();
    const authScreen = document.getElementById('authScreen');
    const otpScreen = document.getElementById('loginOtpScreen');

    if (data.authenticated && !data.otp_pending) {
        authScreen.classList.add('opacity-0', 'pointer-events-none');
        otpScreen.classList.add('hidden');
        updateUserUI(data.name);
        await loadFolders();
        await loadDocumentsFromDB();
        await renderKycStatusUI();
        switchTab(currentTab);
    } else if (data.otp_pending) {
        authScreen.classList.add('opacity-0', 'pointer-events-none');
        showLoginOtpScreen();
    } else {
        authScreen.classList.remove('opacity-0', 'pointer-events-none');
    }
}

async function handleAuthSubmit(event) {
    event.preventDefault();
    const email = document.getElementById('authEmail').value.trim();
    const password = document.getElementById('authPassword').value;
    const name = document.getElementById('authName').value.trim();

    const url = isLoginMode ? '/api/auth/login' : '/api/auth/signup';
    const payload = isLoginMode ? { email, password } : { email, password, name };

    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const result = await res.json();

    if (res.ok && result.otp_required) {
        // Show demo OTP hint and the OTP entry screen
        document.getElementById('demoOtpHint').textContent = `Demo OTP: ${result.demo_otp}`;
        showLoginOtpScreen();
    } else if (!res.ok) {
        alert(result.error);
    }
}

function showLoginOtpScreen() {
    document.getElementById('authScreen').classList.add('opacity-0', 'pointer-events-none');
    const s = document.getElementById('loginOtpScreen');
    s.classList.remove('hidden');
    setTimeout(() => s.classList.remove('opacity-0'), 10);
}

async function handleLoginOtpSubmit(event) {
    event.preventDefault();
    const otp = document.getElementById('loginOtpInput').value.trim();

    const res = await fetch('/api/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp })
    });
    const result = await res.json();

    if (res.ok) {
        document.getElementById('loginOtpScreen').classList.add('hidden', 'opacity-0');
        updateUserUI(result.name);
        await loadFolders();
        await loadDocumentsFromDB();
        await renderKycStatusUI();
        switchTab('dashboard');
    } else {
        alert(result.error);
    }
}

async function handleLogOut() {
    await fetch('/api/auth/logout', { method: 'POST' });
    savedDocuments = [];
    savedFolders = [];
    activeFolderId = null;
    document.getElementById('authScreen').classList.remove('opacity-0', 'pointer-events-none');
    toggleAuthMode(false);
}

function toggleAuthMode(toLogin) {
    isLoginMode = toLogin;
    document.getElementById('authForm').reset();
    const nameGroup = document.getElementById('nameFieldGroup');
    const btn = document.getElementById('authSubmitBtn');
    const toggle = document.getElementById('authToggleText');
    const title = document.getElementById('authTitle');
    const sub = document.getElementById('authSubtitle');

    if (isLoginMode) {
        title.textContent = "Welcome Back to Vault";
        sub.textContent = "Enter your keys to decrypt your digital files";
        nameGroup.classList.add('hidden');
        document.getElementById('authName').removeAttribute('required');
        btn.textContent = "Decrypt & Access";
        toggle.innerHTML = `New to SecureVault? <button onclick="toggleAuthMode(false)" class="text-blue-600 font-bold ml-1 hover:underline">Create Account</button>`;
    } else {
        title.textContent = "Create Your Secure Wallet";
        sub.textContent = "Set up an account to securely store encrypted documents";
        nameGroup.classList.remove('hidden');
        document.getElementById('authName').setAttribute('required', '');
        btn.textContent = "Create Account";
        toggle.innerHTML = `Already have a secure vault? <button onclick="toggleAuthMode(true)" class="text-blue-600 font-bold ml-1 hover:underline">Log In</button>`;
    }
}

// ─── KYC ─────────────────────────────────────────────────────
async function renderKycStatusUI() {
    const res = await fetch('/api/user/kyc');
    if (!res.ok) return;
    const user = await res.json();

    const banner = document.getElementById('kycStatusBanner');
    const iconContainer = document.getElementById('kycBannerIconContainer');
    const icon = document.getElementById('kycBannerIcon');
    const title = document.getElementById('kycStatusTitle');
    const description = document.getElementById('kycStatusDescription');
    const mobileDisplay = document.getElementById('profileMobileDisplay');
    const actionBlock = document.getElementById('mobileKycVerificationBlock');
    const badgeDot = document.getElementById('sidebarKycDot');
    const badgeText = document.getElementById('sidebarKycText');

    if (user.kycVerified) {
        banner.className = "flex items-center gap-4 p-5 bg-emerald-50 border border-emerald-100 rounded-2xl";
        iconContainer.className = "bg-emerald-500 text-white p-3 rounded-xl shadow-md";
        icon.setAttribute('data-lucide', 'shield-check');
        title.className = "font-bold text-emerald-900";
        title.textContent = "Identity Tier 2 Fully Verified";
        description.textContent = "Mobile linking verified. Full storage limits active.";
        mobileDisplay.textContent = `+91 ••••• ••${user.phoneNumber.slice(-4)}`;
        actionBlock.classList.add('hidden');
        badgeDot.className = "w-2 h-2 bg-emerald-500 rounded-full inline-block ring-2 ring-emerald-100";
        badgeText.className = "text-emerald-600 font-bold";
        badgeText.textContent = "Tier 2 Verified";
    } else {
        banner.className = "flex items-center gap-4 p-5 bg-amber-50/60 border border-amber-100 rounded-2xl";
        iconContainer.className = "bg-amber-500 text-white p-3 rounded-xl shadow-md";
        icon.setAttribute('data-lucide', 'alert-circle');
        title.className = "font-bold text-amber-900";
        title.textContent = "Identity Tier 1 Unverified";
        description.textContent = "Link and verify your mobile number to unlock full storage.";
        mobileDisplay.textContent = "Not Linked";
        actionBlock.classList.remove('hidden');
        badgeDot.className = "w-2 h-2 bg-amber-500 rounded-full inline-block ring-2 ring-amber-100 animate-pulse";
        badgeText.className = "text-amber-600 font-bold";
        badgeText.textContent = "Tier 1 Identity";
    }
    lucide.createIcons();
}

function sendKycOtp(event) {
    event.preventDefault();
    const phone = document.getElementById('kycPhoneInput').value;
    if (phone.length !== 10) return alert("Please enter a valid 10-digit number.");
    pendingKycMobile = phone;
    toggleOtpModal(true);
}

async function verifyKycOtp(event) {
    event.preventDefault();
    const otp = document.getElementById('otpInput').value;
    const res = await fetch('/api/user/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp, phone: pendingKycMobile })
    });
    const result = await res.json();
    if (res.ok) {
        toggleOtpModal(false);
        document.getElementById('mobileKycForm').reset();
        await renderKycStatusUI();
        alert(result.message);
    } else {
        alert(result.error + " Hint: Use '1234'");
    }
}

function toggleOtpModal(show) {
    const modal = document.getElementById('otpModal');
    if (show) {
        modal.classList.remove('hidden');
        setTimeout(() => { modal.classList.remove('opacity-0'); modal.querySelector('div').classList.remove('scale-95'); }, 10);
    } else {
        modal.classList.add('opacity-0');
        modal.querySelector('div').classList.add('scale-95');
        setTimeout(() => { modal.classList.add('hidden'); document.getElementById('otpInput').value = ""; }, 300);
    }
}

// ─── FOLDERS ─────────────────────────────────────────────────
async function loadFolders() {
    const res = await fetch('/api/folders');
    if (res.ok) {
        savedFolders = await res.json();
        renderFolderList();
    }
}

function renderFolderList() {
    const container = document.getElementById('folderList');
    if (!container) return;
    container.innerHTML = '';

    // "All Files" entry
    const allBtn = document.createElement('button');
    allBtn.className = `folder-card w-full flex items-center gap-2 px-3 py-2 rounded-xl border text-sm font-semibold mb-1 ${activeFolderId === null ? 'active-folder border-blue-300 text-blue-700' : 'border-slate-200 text-slate-600 hover:bg-slate-50'}`;
    allBtn.innerHTML = `<i data-lucide="layers" class="w-4 h-4"></i> All Files`;
    allBtn.onclick = () => { activeFolderId = null; loadDocumentsFromDB(); renderFolderList(); };
    container.appendChild(allBtn);

    savedFolders.forEach(f => {
        const row = document.createElement('div');
        row.className = `folder-card flex items-center justify-between px-3 py-2 rounded-xl border mb-1 ${activeFolderId === f.id ? 'active-folder border-blue-300' : 'border-slate-200 hover:bg-slate-50'}`;
        row.innerHTML = `
            <button class="flex items-center gap-2 text-sm font-semibold text-slate-700 flex-1 text-left" onclick="openFolder(${f.id})">
                <i data-lucide="folder" class="w-4 h-4 text-amber-500"></i> ${escHtml(f.name)}
            </button>
            <button onclick="deleteFolder(${f.id})" class="text-rose-400 hover:text-rose-600 ml-2 p-1 rounded-lg hover:bg-rose-50 transition-colors">
                <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
            </button>
        `;
        container.appendChild(row);
    });

    lucide.createIcons();
}

function openFolder(folderId) {
    activeFolderId = folderId;
    renderFolderList();
    loadDocumentsFromDB();
}

async function createFolder() {
    const name = prompt("Enter folder name:");
    if (!name || !name.trim()) return;
    const res = await fetch('/api/folders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim() })
    });
    if (res.ok) {
        await loadFolders();
    } else {
        const e = await res.json();
        alert(e.error);
    }
}

async function deleteFolder(folderId) {
    if (!confirm("Delete this folder? Documents inside will be moved to root.")) return;
    const res = await fetch(`/api/folders/${folderId}`, { method: 'DELETE' });
    if (res.ok) {
        if (activeFolderId === folderId) activeFolderId = null;
        await loadFolders();
        await loadDocumentsFromDB();
    }
}

// Populate folder dropdown in upload modal
function populateFolderSelect() {
    const sel = document.getElementById('uploadFolderSelect');
    if (!sel) return;
    sel.innerHTML = '<option value="">— No Folder (Root) —</option>';
    savedFolders.forEach(f => {
        const opt = document.createElement('option');
        opt.value = f.id;
        opt.textContent = f.name;
        sel.appendChild(opt);
    });
}

// ─── DOCUMENTS ───────────────────────────────────────────────
async function loadDocumentsFromDB() {
    const url = activeFolderId ? `/api/documents?folder_id=${activeFolderId}` : '/api/documents';
    const res = await fetch(url);
    if (res.ok) {
        savedDocuments = await res.json();
        renderStoredCards();
        updateStatsCounters();
    }
}

function renderStoredCards() {
    const grid = document.getElementById('documentGrid');
    grid.innerHTML = '';

    if (savedDocuments.length === 0) {
        grid.innerHTML = `<div class="col-span-3 text-center py-16 text-slate-400 font-medium">
            <i data-lucide="inbox" class="w-10 h-10 mx-auto mb-3 opacity-40"></i>
            <p>No documents found</p>
        </div>`;
        lucide.createIcons();
        return;
    }

    savedDocuments.forEach(doc => {
        let badgeColor = "bg-blue-50 border-blue-100 text-blue-600";
        let datasource = "uploaded";
        let tagLabel = "Saved";

        if (doc.type === "Govt ID") { badgeColor = "bg-amber-50 border-amber-100 text-amber-600"; datasource = "issued"; tagLabel = "Verified"; }
        if (doc.type === "Education") badgeColor = "bg-purple-50 border-purple-100 text-purple-600";
        if (doc.type === "Transport") badgeColor = "bg-rose-50 border-rose-100 text-rose-600";

        const isPreviewable = doc.mime && (doc.mime.startsWith('image/') || doc.mime === 'application/pdf');
        const folderName = doc.folderId ? (savedFolders.find(f => f.id === doc.folderId) || {}).name || '' : '';

        grid.insertAdjacentHTML('beforeend', `
            <div class="bg-white border border-slate-200/70 rounded-3xl shadow-sm hover:shadow-md hover:border-slate-300 transition-all duration-300 overflow-hidden flex flex-col justify-between group doc-card" data-source="${datasource}">
                <div class="p-6">
                    <div class="flex items-start justify-between mb-4">
                        <div class="${badgeColor} border px-3 py-1 rounded-xl font-bold text-[11px] uppercase tracking-wider">${doc.type}</div>
                        <span class="bg-emerald-50 text-emerald-700 text-xs font-semibold px-2.5 py-1 rounded-full border border-emerald-100 flex items-center gap-1">
                            <span class="w-1.5 h-1.5 bg-emerald-500 rounded-full"></span> ${tagLabel}
                        </span>
                    </div>
                    <h4 class="font-extrabold text-slate-800 text-base group-hover:text-blue-600 transition-colors mb-1 truncate">${escHtml(doc.name)}</h4>
                    <p class="text-xs font-medium text-slate-400 mb-2">Size: ${doc.size}</p>
                    <div class="flex items-center gap-2 flex-wrap">
                        <span class="lock-badge"><i data-lucide="lock" class="w-2.5 h-2.5"></i> AES-256</span>
                        <span class="dl-badge"><i data-lucide="download" class="w-2.5 h-2.5"></i> ${doc.downloadCount} dl</span>
                        ${folderName ? `<span class="text-[11px] font-semibold text-amber-600 bg-amber-50 border border-amber-100 px-2 py-0.5 rounded-full"><i data-lucide="folder" class="w-2.5 h-2.5 inline"></i> ${escHtml(folderName)}</span>` : ''}
                    </div>
                </div>
                <div class="bg-slate-50 px-6 py-3.5 border-t border-slate-100 flex items-center justify-between">
                    <span class="text-xs text-slate-400 font-medium">#${doc.id}</span>
                    <div class="flex items-center gap-3">
                        <button onclick="toggleFavorite(${doc.id})" class="${doc.favorite ? 'text-amber-500' : 'text-slate-300 hover:text-amber-400'} transition-colors" title="Favorite">
                            <i data-lucide="star" class="w-4 h-4"></i>
                        </button>
                        <button onclick="downloadDoc(${doc.id})" class="text-slate-400 hover:text-blue-600 transition-colors" title="Download">
                            <i data-lucide="download" class="w-4 h-4"></i>
                        </button>
                        ${isPreviewable ? `<button onclick="previewDocument(${doc.id}, '${escHtml(doc.name)}', '${doc.mime}')" class="text-blue-600 hover:text-blue-700 font-bold text-sm flex items-center gap-1">
                            View <i data-lucide="arrow-up-right" class="w-4 h-4"></i>
                        </button>` : ''}
                        <button onclick="deleteDocument(${doc.id})" class="text-rose-400 hover:text-rose-600 transition-colors" title="Delete">
                            <i data-lucide="trash-2" class="w-4 h-4"></i>
                        </button>
                    </div>
                </div>
            </div>
        `);
    });
    lucide.createIcons();
}

async function deleteDocument(docId) {
    if (!confirm("Permanently delete this document?")) return;
    const res = await fetch(`/api/documents/delete/${docId}`, { method: 'DELETE' });
    if (res.ok) { await loadDocumentsFromDB(); }
    else alert("Failed to delete document.");
}

async function toggleFavorite(docId) {
    await fetch(`/api/documents/favorite/${docId}`, { method: 'PUT' });
    await loadDocumentsFromDB();
}

function downloadDoc(docId) {
    // Triggers download and increments counter server-side
    window.location.href = `/api/documents/download/${docId}`;
    // Refresh after short delay to update download count badge
    setTimeout(loadDocumentsFromDB, 1500);
}

// ─── UPLOAD ──────────────────────────────────────────────────
function initDragDrop() {
    const zone = document.getElementById('dropZone');
    if (!zone) return;

    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length) {
            document.getElementById('fileInput').files = files;
            updateFileLabel(files);
        }
    });
}

function updateFileLabel(files) {
    const label = document.getElementById('fileName');
    if (files.length === 1) {
        label.textContent = files[0].name;
    } else {
        label.textContent = `${files.length} files selected`;
    }
    label.classList.add('text-blue-600');
}

function updateFileName(input) {
    if (input.files.length > 0) updateFileLabel(input.files);
}

async function handleUpload(event) {
    event.preventDefault();
    const files = document.getElementById('fileInput').files;
    if (!files.length) return alert("Please select at least one file.");

    const formData = new FormData();
    formData.append('type', document.getElementById('docType').value);
    formData.append('category', 'General');

    const folderId = document.getElementById('uploadFolderSelect').value;
    if (folderId) formData.append('folder_id', folderId);

    // Append all files under 'files[]'
    for (const file of files) {
        formData.append('files[]', file);
    }

    const res = await fetch('/api/documents/upload', { method: 'POST', body: formData });
    const result = await res.json();

    if (res.ok) {
        if (result.errors && result.errors.length) alert("Some files failed:\n" + result.errors.join('\n'));
        document.getElementById('uploadForm').reset();
        document.getElementById('fileName').textContent = "Drop files here or click to browse";
        document.getElementById('fileName').classList.remove('text-blue-600');
        toggleUploadModal(false);
        await loadDocumentsFromDB();
        switchTab('uploaded');
    } else {
        alert(result.error || "Upload failed");
    }
}

// ─── PREVIEW ─────────────────────────────────────────────────
function previewDocument(docId, name, mime) {
    document.getElementById('viewerTitle').textContent = name;
    const container = document.getElementById('viewerContent');
    const url = `/api/documents/view/${docId}`;

    if (mime === 'application/pdf') {
        container.innerHTML = `<iframe id="previewFrame" src="${url}"></iframe>`;
    } else if (mime.startsWith('image/')) {
        container.innerHTML = `<img id="previewImg" src="${url}" alt="${escHtml(name)}">`;
    } else {
        container.innerHTML = `<p class="text-slate-400 font-medium">Preview not available for this file type.</p>`;
    }
    openViewerModal();
}

// Keep legacy function name working
function viewUploadedDocument(docId, name) {
    const doc = savedDocuments.find(d => d.id === docId);
    const mime = doc ? doc.mime : '';
    previewDocument(docId, name, mime);
}

function openViewerModal() {
    const modal = document.getElementById('viewerModal');
    modal.classList.remove('hidden');
    setTimeout(() => { modal.classList.remove('opacity-0'); modal.querySelector('div').classList.remove('scale-95'); }, 10);
    lucide.createIcons();
}

function closeViewerModal() {
    const modal = document.getElementById('viewerModal');
    modal.classList.add('opacity-0');
    modal.querySelector('div').classList.add('scale-95');
    setTimeout(() => { modal.classList.add('hidden'); document.getElementById('viewerContent').innerHTML = ''; }, 300);
}

// ─── CHART.JS STATS ──────────────────────────────────────────
async function loadMonthlyChart() {
    const res = await fetch('/api/dashboard/monthly-stats');
    if (!res.ok) return;
    const data = await res.json();

    const labels = data.map(d => d.month);
    const counts = data.map(d => d.count);

    const ctx = document.getElementById('uploadChart');
    if (!ctx) return;

    if (uploadChart) uploadChart.destroy();

    uploadChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Uploads',
                data: counts,
                backgroundColor: 'rgba(59,130,246,0.7)',
                borderColor: '#3b82f6',
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, ticks: { stepSize: 1 } }
            }
        }
    });
}

// ─── UI HELPERS ──────────────────────────────────────────────
function updateUserUI(name) {
    document.getElementById('sidebarUserName').textContent = name;
    document.getElementById('profileFullName').textContent = name;
    document.getElementById('headerTitle').textContent = `Welcome back, ${name.split(' ')[0]}`;
    const initials = name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
    document.getElementById('profileAvatar').textContent = initials || "U";
}

function updateStatsCounters() {
    document.getElementById('issuedCount').textContent =
        `${savedDocuments.length} ${savedDocuments.length === 1 ? 'Document' : 'Documents'}`;
    let totalBytes = 0;
    savedDocuments.forEach(d => {
        const mb = parseFloat(d.size);
        if (!isNaN(mb)) totalBytes += mb * 1024 * 1024;
    });
    document.getElementById('storageText').textContent =
        `${(totalBytes / 1024 / 1024).toFixed(2)} MB / 5 MB`;
}

function switchTab(tabName) {
    currentTab = tabName;
    const firstName = (document.getElementById('sidebarUserName').textContent || "User").split(' ')[0];
    const headerTitle = document.getElementById('headerTitle');
    const sectionTitle = document.getElementById('sectionTitle');
    const docWrapper = document.getElementById('documentViewWrapper');
    const statsSection = document.getElementById('statsSection');
    const profilePanel = document.getElementById('profilePanel');
    const chartSection = document.getElementById('chartSection');

    document.querySelectorAll('.nav-link').forEach(link => {
        const active = link.getAttribute('data-tab') === tabName;
        link.className = active
            ? "w-full flex items-center gap-3.5 px-4 py-3.5 bg-blue-50 text-blue-600 rounded-2xl font-semibold transition-all group nav-link text-sm shadow-sm border border-blue-100/20"
            : "w-full flex items-center gap-3.5 px-4 py-3.5 text-slate-600 hover:bg-slate-50 hover:text-slate-900 rounded-2xl font-semibold transition-all group nav-link text-sm border border-transparent";
    });

    profilePanel.classList.add('hidden');
    docWrapper.classList.remove('hidden');
    chartSection && chartSection.classList.add('hidden');

    if (tabName === 'profile') {
        docWrapper.classList.add('hidden');
        profilePanel.classList.remove('hidden');
        headerTitle.textContent = "Profile Settings";
    } else if (tabName === 'dashboard') {
        statsSection.classList.remove('hidden');
        chartSection && chartSection.classList.remove('hidden');
        sectionTitle.textContent = "Your Digital Wallet";
        headerTitle.textContent = `Welcome back, ${firstName}`;
        loadMonthlyChart();
        document.querySelectorAll('.doc-card').forEach(c => c.classList.remove('hidden'));
    } else if (tabName === 'issued') {
        statsSection.classList.add('hidden');
        sectionTitle.textContent = "Official Issued Documents";
        headerTitle.textContent = "Issued Wallet";
        document.querySelectorAll('.doc-card').forEach(c =>
            c.getAttribute('data-source') === 'issued' ? c.classList.remove('hidden') : c.classList.add('hidden'));
    } else if (tabName === 'uploaded') {
        statsSection.classList.add('hidden');
        sectionTitle.textContent = "Your Cloud Drive Uploads";
        headerTitle.textContent = "Cloud Storage";
        document.querySelectorAll('.doc-card').forEach(c =>
            c.getAttribute('data-source') === 'uploaded' ? c.classList.remove('hidden') : c.classList.add('hidden'));
    }
}

function toggleUploadModal(show) {
    const modal = document.getElementById('uploadModal');
    if (show) {
        populateFolderSelect();
        modal.classList.remove('hidden');
        setTimeout(() => { modal.classList.remove('opacity-0'); modal.querySelector('div').classList.remove('scale-95'); }, 10);
    } else {
        modal.classList.add('opacity-0');
        modal.querySelector('div').classList.add('scale-95');
        setTimeout(() => modal.classList.add('hidden'), 300);
    }
}

function escHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
