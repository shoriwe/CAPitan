let selectedInterface = "";
let connection = undefined;

const exampleOption = {
    xAxis: {
        type: 'category',
        data: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    },
    yAxis: {
        type: 'value'
    },
    series: [
        {
            data: [150, 230, 224, 218, 135, 147, 260],
            type: 'line'
        }
    ]
};

const topologyGraph = echarts.init(document.getElementById("topology-graph"));
const barPlotNumberOfPacketsPerHost = echarts.init(document.getElementById("number-of-packets-send-per-host"));
const pieNumberOfPacketsPerLayer4 = echarts.init(document.getElementById("layer-4"));
const pieNumberOfStreamsPerTypes = echarts.init(document.getElementById("streams-type"));
const bandwidth = echarts.init(document.getElementById("bandwidth"));
// topologyGraph.setOption(exampleOption);
// barPlotNumberOfPacketsPerHost.setOption(exampleOption);
// pieNumberOfPacketsPerLayer4.setOption(exampleOption);
// pieNumberOfStreamsPerTypes.setOption(exampleOption);
// bandwidth.setOption(exampleOption);

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

function newSeparator() {
    const separator = document.createElement("span");
    separator.style.width = "1%";
    return separator;
}

async function loadPacket(packet) {
    const newEntry = document.createElement("div");
    newEntry.classList.add("list-entry");
    newEntry.style.width = "90%";

    const src = document.createElement("h3");
    src.innerText = `${packet.NetworkLayer.LinkFlow.Src}:${packet.TransportLayer.TransportFlow.Src}`;
    src.classList.add("blue-text");
    src.style.minWidth = "22%";

    const dst = document.createElement("h3");
    dst.classList.add("red-text");
    dst.innerText = `${packet.NetworkLayer.LinkFlow.Dst}:${packet.TransportLayer.TransportFlow.Dst}`;
    dst.style.minWidth = "22%";

    const layerType = document.createElement("h3");
    layerType.classList.add("green-text");
    layerType.innerText = `${packet.NetworkLayer.LayerType}:${packet.TransportLayer.LayerType}`;
    layerType.style.minWidth = "22%";

    const applicationLayer = document.createElement("h3");
    applicationLayer.classList.add("black-text");
    applicationLayer.innerText = packet.ApplicationLayer.LayerType
    applicationLayer.style.minWidth = "22%";

    const viewButton = document.createElement("button");
    viewButton.classList.add("blue-button");
    viewButton.innerText = "Details"
    viewButton.onclick = function () {
        document.getElementById("packet-as-json").innerText = "\r" + JSON.stringify(packet, null, 2);
        document.getElementById("packet-dialog").style.display = "block";
    }

    newEntry.append(src);
    newEntry.append(newSeparator());
    newEntry.append(dst);
    newEntry.append(newSeparator());
    newEntry.append(layerType);
    newEntry.append(newSeparator());
    newEntry.append(applicationLayer);
    newEntry.append(newSeparator());
    newEntry.append(viewButton);


    document.getElementById("packets-list").append(newEntry);
}

function createParentDiv() {
    const result = document.createElement("div");
    result.style.margin = "1%";
    result.style.minWidth = "45vw";
    result.style.height = "50vh";
    return result;
}

function createCodeBlock() {
    const result = document.createElement("pre")
    result.style.height = "40vh";
    const code = document.createElement("code");
    result.append(code);
    return result;
}

function newText(contentType, content) {
    const subType = contentType.split("/")[1];
    const textBlock = createParentDiv();

    const title = document.createElement("h3");
    title.classList.add("blue-text");
    title.innerText = "Text " + subType;

    const data = createCodeBlock();
    data.innerHTML = atob(content);
    data.classList.add("language-" + subType);
    Prism.highlightElement(data);

    textBlock.append(title);
    textBlock.append(data);

    return textBlock;
}

function newUnknown(content) {
    const unknown = createParentDiv();

    const title = document.createElement("h3");
    title.classList.add("blue-text");
    title.innerText = "Unknown (Base64 encoded)";

    const data = createCodeBlock();
    data.innerText = content;
    Prism.highlightElement(data);

    unknown.append(title);
    unknown.append(data);

    return unknown;
}

function newImage(contentType, content) {
    const image = createParentDiv();

    const title = document.createElement("h3");
    title.classList.add("blue-text");
    title.innerText = "Image";

    const img = document.createElement("img");
    img.src = `data:${contentType};base64, ${content}`;

    image.append(title);
    image.append(img);

    return image;
}

async function loadStream(stream) {
    if (stream.Type.indexOf("image/") === 0) {
        document.getElementById("streams-container").append(newImage(stream.Type, stream.Content));
        return;
    } else if (stream.Type.indexOf("text/") === 0) {
        document.getElementById("streams-container").append(newText(stream.Type, stream.Content));
        return;
    } else if (stream.Type.indexOf("application/") === 0) {
        document.getElementById("streams-container").append(newText(stream.Type, stream.Content));
        return;
    }
    switch (stream.Type) {
        case "unknown":
            document.getElementById("streams-container").append(newUnknown(stream.Content));
            break;
        default:
            console.log(stream.Type);
            break;
    }
}

async function updateTopology(data) {
    console.log("HERE");
    const newTopology = {
        tooltip: {},
        // legend: [
        //     {
        //         data: data.Categories.map(function (a) {
        //             return a.name;
        //         })
        //     }
        // ],
        series: [
            {
                name: 'Les Miserables',
                type: 'graph',
                layout: 'circular',
                data: data.Vertices,
                links: data.Edges,
                categories: data.Categories,
                roam: true,
                edgeSymbol: ['circle', 'arrow'],
                edgeSymbolSize: [4, 10],
                circular: {
                    rotateLabel: true
                },
                label: {
                    show: true,
                    position: 'right',
                    formatter: '{b}'
                },
                labelLayout: {
                    hideOverlap: true
                },
                scaleLimit: {
                    min: 0.4,
                    max: 2
                },
                lineStyle: {
                    color: 'source',
                    curveness: 0.3
                }
            }
        ]
    };
    console.log(JSON.stringify(newTopology));
    topologyGraph.setOption(newTopology);
}

async function updateGraphs(data) {
    switch (data.Target) {
        case "topology":
            updateTopology(data.Options);
            break;
    }
}

async function newCapture() {
    const value = await testNewCaptureInformation();
    const errorMessage = document.getElementById("error-message");
    if (!value.Succeed) {
        errorMessage.innerHTML = value.Error;
        errorMessage.style.display = "block";
        return
    }
    // TODO: Change the page and start the capture
    const target = "ws://" + document.location.host + "/packet/captures?action=start";
    connection = new WebSocket(target, "PacketCaptureSession");

    connection.onopen = function (_) {
        errorMessage.style.display = "none";
        document.getElementById("new-config-container").style.display = "none";
        document.getElementById("capture-session-container").style.display = "block"

        const captureName = document.getElementById("capture-name");
        const description = document.getElementById("description");
        const filterScript = document.getElementById("filter-script");
        const promiscuousCheckbox = document.getElementById("promiscuous");
        const configuration = JSON.stringify(
            {
                InterfaceName: selectedInterface,
                CaptureName: captureName.value,
                Description: description.value,
                Script: filterScript.value,
                Promiscuous: promiscuousCheckbox.checked
            }
        );
        connection.send(configuration);
        document.getElementById("title").innerText = captureName.value;
    }

    connection.onmessage = function (message) {
        const data = JSON.parse(message.data);
        switch (data.Type) {
            case "packet":
                loadPacket(data.Payload);
                break;
            case "stream":
                loadStream(data.Payload);
                break;
            case "update-graphs":
                updateGraphs(data.Payload);
                break;
        }
    };
}

function stopCapture() {
    connection.send({
            Action: "STOP",
        }
    )
}

function selectCaptureInterface(id) {
    document.getElementById("capture").textContent = id;
    selectedInterface = id;
}

function tcpStreamMenu() {
    document.getElementById("tcp-stream-menu").style.display = "block"
    document.getElementById("packet-menu").style.display = "none"
    document.getElementById("data-analysis-menu").style.display = "none"
}

function packetMenu() {
    document.getElementById("packet-menu").style.display = "block"
    document.getElementById("tcp-stream-menu").style.display = "none"
    document.getElementById("data-analysis-menu").style.display = "none"
}

function dataAnalysisMenu() {
    document.getElementById("data-analysis-menu").style.display = "block"
    document.getElementById("packet-menu").style.display = "none"
    document.getElementById("tcp-stream-menu").style.display = "none"
}