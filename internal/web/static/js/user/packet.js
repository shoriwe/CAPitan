let selectedInterface = "";

function togglePromiscuous() {
    const promiscuous = document.getElementById("promiscuous");
    promiscuous.checked = !promiscuous.checked;
    const promiscuousCheckbox = document.getElementById("promiscuous-checkbox");
    if (promiscuous.checked) {
        promiscuousCheckbox.classList.remove("unchecked-checkbox");
        promiscuousCheckbox.classList.add("checked-checkbox");
        promiscuousCheckbox.textContent = "Promiscuous";
    } else {
        promiscuousCheckbox.classList.add("unchecked-checkbox");
        promiscuousCheckbox.classList.remove("checked-checkbox");
        promiscuousCheckbox.textContent = "Non Promiscuous";
    }
}

async function testNewCaptureInformation() {
    const captureName = document.getElementById("capture-name");
    const description = document.getElementById("description");
    const filterScript = document.getElementById("filter-script");
    const promiscuousCheckbox = document.getElementById("promiscuous");
    let promiscuous = "";
    if (promiscuousCheckbox.checked) {
        promiscuous = "checked";
    }
    const formBody = [
        "interface=" + encodeURIComponent(selectedInterface),
        "capture-name=" + encodeURIComponent(captureName.value),
        "description=" + encodeURIComponent(description.value),
        "script=" + encodeURIComponent(filterScript.value),
        "promiscuous=" + encodeURIComponent(promiscuous)
    ];
    return fetch(
        "/packet/captures?action=test",
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

async function newCapture() {
    const value = await testNewCaptureInformation();
    const errorMessage = document.getElementById("error-message");
    if (!value.Succeed) {
        console.log(value.Error);
        errorMessage.innerHTML = value.Error;
        errorMessage.style.display = "block";
        return
    }
    // TODO: Change the page and start the capture
    const target = "ws://" + document.location.host + "/packet/captures?action=start";
    alert(target);
    const connection = new WebSocket(target, "PacketCaptureSession");

    connection.onopen = function (event) {
        errorMessage.style.display = "none";
        document.getElementById("new-config-container").style.display = "none";
        document.getElementById("capture-session-container").style.display = "block"

        const captureName = document.getElementById("capture-name");
        const description = document.getElementById("description");
        const filterScript = document.getElementById("filter-script");
        const promiscuousCheckbox = document.getElementById("promiscuous");
        alert("SENDING DATA");
        const configuration = JSON.stringify(
            {
                InterfaceName: selectedInterface,
                CaptureName: captureName.value,
                Description: description.value,
                FilterScript: filterScript.value,
                Promiscuous: promiscuousCheckbox.checked
            }
        );
        alert("DATA send");
        connection.send(configuration);
    }
    connection.onmessage = function (message) {
        alert(message);
    };
}

function selectCaptureInterface(id) {
    document.getElementById("capture").textContent = id;
    selectedInterface = id;
}