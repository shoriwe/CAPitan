let selectedInterface = undefined;

function selectARPSpoofInterface(id) {
    selectedInterface = id;
    document.getElementById("spoof").textContent = id;
}

function checkIP(ip) {
    if ((new RegExp("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")).test(ip)) {
        return true;
    }
    const ipv6Regexp = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/gi;
    return ipv6Regexp.test(ip);
}

function testInput(ip, arpInterface) {
    const formBody = [
        "ip=" + encodeURIComponent(ip),
        "interface=" + encodeURIComponent(arpInterface),
    ];
    return fetch(
        "/arp/spoof?action=test",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formBody.join("&")
        }
    ).then(response => {
        return response.json();
    });
}

async function startSpoof() {
    const ip = document.getElementById("target").value;
    // Check if the IP set is valid
    if (!checkIP(ip)) {
        document.getElementById("error-message").innerText = "Invalid IP provided";
        document.getElementById("error-message").style.display = "block";
        return;
    }
    if (selectedInterface === undefined || selectedInterface.length === 0) {
        document.getElementById("error-message").innerText = "No interface provided";
        document.getElementById("error-message").style.display = "block";
        return;
    }
    const result = await testInput(ip, selectedInterface);
    if (!result.Succeed) {
        document.getElementById("error-message").innerText = result.Message;
        document.getElementById("error-message").style.display = "block";
        return;
    }
    document.getElementById("error-message").style.display = "none";
    // TODO: Start the ARP Spoofing session
}