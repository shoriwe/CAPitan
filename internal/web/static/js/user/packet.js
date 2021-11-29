let selectedInterface = "";

async function testNewCaptureInformation() {
    const captureName = document.getElementById("capture-name");
    const description = document.getElementById("description");
    const filterScript = document.getElementById("filter-script");
    const formBody = [
        "interface=" + encodeURIComponent(selectedInterface),
        "capture-name=" + encodeURIComponent(captureName.value),
        "description=" + encodeURIComponent(description.value),
        "script=" + encodeURIComponent(filterScript.value)
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
    errorMessage.style.display = "none";
    // TODO: Change the page and start the capture
    return
}

function selectCaptureInterface(id) {
    document.getElementById("capture").textContent = id;
    selectedInterface = id;
}