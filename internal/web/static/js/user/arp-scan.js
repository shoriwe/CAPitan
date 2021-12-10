let selectedInterface = undefined;
let connection = undefined;

function selectARPScanInterface(id) {
    selectedInterface = id;
    document.getElementById("scan").textContent = id;
}

function stopScan() {
    const message = {
        Action: "STOP"
    }
    connection.send(JSON.stringify(message));
    connection.onmessage = function (event) {
        const data = JSON.parse(event.data)
        if (data.Succeed) {
            document.location.href = "/arp/scan?action=list";
        }
    }
}

function addHost(hostInformation) {
    const results = document.getElementById("results");
    const entry = document.createElement("div");
    entry.classList.add("list-entry");
    const ip = document.createElement("h3")
    ip.classList.add("blue-text");
    ip.innerText = hostInformation.IP;
    const mac = document.createElement("h3");
    mac.classList.add("black-text");
    mac.innerText = hostInformation.MAC;
    const span = document.createElement("span");
    span.style.width = "1%";
    entry.append(ip);
    entry.append(span);
    entry.append(mac);
    results.append(entry);
}

async function startScan() {
    const scanName = document.getElementById("scan-name").value;
    const script = document.getElementById("hosts-script").value;
    const errorMessage = document.getElementById("error-message");
    const setupMenu = document.getElementById("setup-menu");
    const resultsMenu = document.getElementById("results-menu");

    const target = "ws://" + document.location.host + "/arp/scan?action=new";
    connection = new WebSocket(target, "ARPScanSession");

    connection.onopen = function (_) {
        const configuration = JSON.stringify(
            {
                ScanName: scanName,
                InterfaceName: selectedInterface,
                Script: script,
            }
        );
        connection.send(configuration);

        connection.onmessage = function (message) {
            const data = JSON.parse(message.data);
            if (data.Succeed) {
                errorMessage.style.display = "none";
                setupMenu.style.display = "none";
                resultsMenu.style.display = "block";
                connection.onmessage = function (message) {
                    const data = JSON.parse(message.data);
                    switch (data.Type) {
                        case "error":
                            errorMessage.style.display = "block";
                            errorMessage.innerText = data.Payload;
                            connection.close(1000);
                            break;
                        case "stop":
                            // TODO: Implement me
                            break;
                        case "host":
                            addHost(data.Payload);
                            break;
                    }
                }
            } else {
                errorMessage.style.display = "block";
                errorMessage.innerText = data.Message;
                connection.close(1000);
            }
        };
    }
}