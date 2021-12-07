let selectedInterface = undefined;
let connection = undefined;

function selectARPSpoofInterface(id) {
    selectedInterface = id;
    document.getElementById("spoof").textContent = id;
}

function testInput(ip, gateway, arpInterface) {
    const formBody = [
        "ip=" + encodeURIComponent(ip),
        "interface=" + encodeURIComponent(arpInterface),
        "gateway=" + encodeURIComponent(gateway)
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
    const ip = document.getElementById("ip").value;
    const gateway = document.getElementById("gateway").value;

    const result = await testInput(ip, gateway, selectedInterface);
    if (!result.Succeed) {
        document.getElementById("error-message").innerText = result.Message;
        document.getElementById("error-message-container").style.display = "block";
        return;
    }
    document.getElementById("error-message-container").style.display = "none";
    // TODO: Start the ARP Spoofing session
    // TODO: Hide the setup menu
    // TODO: Show the ARP spoof active menu
    // TODO: Update the title of the running IP spoofed
}