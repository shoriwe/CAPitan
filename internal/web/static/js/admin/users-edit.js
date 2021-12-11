const isAdmin = document.getElementById("is-admin");
const enabledDisabled = document.getElementById("enabled-disabled");
if (isAdmin.checked) {
    const isAdminCheckbox = document.getElementById("is-admin-checkbox");
    isAdminCheckbox.classList.remove("unchecked-checkbox");
    isAdminCheckbox.classList.add("checked-checkbox");
    isAdminCheckbox.textContent = "Admin";
}

if (enabledDisabled.checked) {
    const enabledDisabledCheckbox = document.getElementById("enabled-disabled-checkbox");
    enabledDisabledCheckbox.classList.remove("unchecked-checkbox");
    enabledDisabledCheckbox.classList.add("checked-checkbox");
    enabledDisabledCheckbox.textContent = "Enabled";
}

function toggleIsAdmin() {
    const isAdmin = document.getElementById("is-admin");
    isAdmin.checked = !isAdmin.checked;
    const isAdminCheckbox = document.getElementById("is-admin-checkbox");
    if (isAdmin.checked) {
        isAdminCheckbox.classList.remove("unchecked-checkbox");
        isAdminCheckbox.classList.add("checked-checkbox");
        isAdminCheckbox.textContent = "Admin";
    } else {
        isAdminCheckbox.classList.add("unchecked-checkbox");
        isAdminCheckbox.classList.remove("checked-checkbox");
        isAdminCheckbox.textContent = "User";
    }
}

function toggleEnabledDisabled() {
    const enabledDisabled = document.getElementById("enabled-disabled");
    enabledDisabled.checked = !enabledDisabled.checked;
    const enabledDisabledCheckbox = document.getElementById("enabled-disabled-checkbox");
    if (enabledDisabled.checked) {
        enabledDisabledCheckbox.classList.remove("unchecked-checkbox");
        enabledDisabledCheckbox.classList.add("checked-checkbox");
        enabledDisabledCheckbox.textContent = "Enabled";
    } else {
        enabledDisabledCheckbox.classList.remove("checked-checkbox");
        enabledDisabledCheckbox.classList.add("unchecked-checkbox");
        enabledDisabledCheckbox.textContent = "Disabled";
    }
}

window.onload = function () {
    if (window.location.href.indexOf('scroll_to=') !== -1) {
        const arguments = window.location.href.split('?')[1].split("&");
        for (let index = 0; index < arguments.length; index++) {
            if (arguments[index].indexOf("scroll_to=") !== -1) {
                const target = arguments[index].split('=')[1]
                document.getElementById(target).scrollIntoView();
            }
        }
    }
}

function reloadPage(target) {
    const reload = document.getElementById("reload-submit");
    reload.action += "&scroll_to=" + target;
    reload.submit();
    return false;
}

function submitUpdatePassword() {
    const username = document.getElementById("resubmit-username").value;
    const password = document.getElementById("password").value;
    document.getElementById("password").value = "";
    const formBody = [];
    formBody.push("username=" + encodeURIComponent(username));
    formBody.push("password=" + encodeURIComponent(password));
    fetch(
        "/admin/user?action=update-password",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formBody.join("&")
        }
    ).then(_ => {

    });
}

function submitUpdateStatus() {
    const username = document.getElementById("resubmit-username").value;
    const isAdmin = document.getElementById("is-admin").checked ? "on" : "";
    const isEnabled = document.getElementById("enabled-disabled").checked ? "on" : "";
    const formBody = [];
    formBody.push("username=" + encodeURIComponent(username));
    formBody.push("is-admin=" + encodeURIComponent(isAdmin));
    formBody.push("is-enabled=" + encodeURIComponent(isEnabled));
    fetch(
        "/admin/user?action=update-status",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formBody.join("&")
        }
    ).then(_ => {
    });
}

function addCaptureInterface(id) {
    const i = id.replace("capture-interface-", "");
    const username = document.getElementById("resubmit-username").value;
    const formBody = [];
    formBody.push("username=" + encodeURIComponent(username));
    formBody.push("interface=" + encodeURIComponent(i));
    fetch(
        "/admin/user?action=add-capture-interface",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formBody.join("&")
        }
    ).then(
        _ => {
            reloadPage("capture-permissions");
        }
    );
}

function deleteCaptureInterface(id) {
    const username = document.getElementById("resubmit-username").value;
    const formBody = [];
    const i = id.replace("capture-interface-to-delete-", "");
    formBody.push("username=" + encodeURIComponent(username));
    formBody.push("interface=" + encodeURIComponent(i));
    fetch(
        "/admin/user?action=delete-capture-interface",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formBody.join("&")
        }
    ).then(
        _ => {
            reloadPage("capture-permissions");
        }
    );
}

function addARPScanInterface(id) {
    const i = id.replace("arp-scan-interface-", "");
    const username = document.getElementById("resubmit-username").value;
    const formBody = [];
    formBody.push("username=" + encodeURIComponent(username));
    formBody.push("interface=" + encodeURIComponent(i));
    fetch(
        "/admin/user?action=add-arp-scan-interface",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formBody.join("&")
        }
    ).then(
        _ => {
            reloadPage("arp-scan-permissions");
        }
    );
}

function deleteARPScanInterface(id) {
    const username = document.getElementById("resubmit-username").value;
    const formBody = [];
    const i = id.replace("arp-scan-interface-to-delete-", "");
    formBody.push("username=" + encodeURIComponent(username));
    formBody.push("interface=" + encodeURIComponent(i));
    fetch(
        "/admin/user?action=delete-arp-scan-interface",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formBody.join("&")
        }
    ).then(
        _ => {
            reloadPage("arp-scan-permissions")
        }
    );
}

function addARPSpoofInterface(id) {
    const i = id.replace("arp-spoof-interface-", "");
    const username = document.getElementById("resubmit-username").value;
    const formBody = [];
    formBody.push("username=" + encodeURIComponent(username));
    formBody.push("interface=" + encodeURIComponent(i));
    fetch(
        "/admin/user?action=add-arp-spoof-interface",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formBody.join("&")
        }
    ).then(
        _ => {
            reloadPage("arp-spoof-permissions");
        }
    );
}

function deleteARPSpoofInterface(id) {
    const username = document.getElementById("resubmit-username").value;
    const formBody = [];
    const i = id.replace("arp-spoof-interface-to-delete-", "");
    formBody.push("username=" + encodeURIComponent(username));
    formBody.push("interface=" + encodeURIComponent(i));
    fetch(
        "/admin/user?action=delete-arp-spoof-interface",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formBody.join("&")
        }
    ).then(
        _ => {
            reloadPage("arp-spoof-permissions");
        }
    );
}