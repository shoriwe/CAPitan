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

function closeConnection() {
    connection.send(JSON.stringify({Action: "STOP"}))
    connection.close(0);
}

async function setupConnection(ip, gateway) {
    const target = "ws://" + document.location.host + "/arp/spoof?action=spoof";
    connection = new WebSocket(target, "ARPSpoofSession");

    connection.onopen = function (_) {
        const configuration = JSON.stringify(
            {
                TargetIP: ip,
                Gateway: gateway,
                InterfaceName: selectedInterface,
            }
        );
        connection.send(configuration);

        connection.onmessage = function (message) {
            const data = JSON.parse(message.data);
            if (data.Succeed) {
                document.getElementById("setup-container").style.display = "none";
                document.getElementById("spoof-container").style.display = "block";
                document.getElementById("spoofed-ip").innerText = ip;
                document.getElementById("spoofed-gateway").innerText = gateway;
                document.getElementById("spoofed-interface").innerText = selectedInterface;
            } else {
                document.getElementById("error-message-container").style.display = "block";
                document.getElementById("error-message-container").innerText = data.Message;
                connection.close(0);
            }
        };
    }
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
    await setupConnection(ip, gateway);
}