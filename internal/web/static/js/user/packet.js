let selectedInterface = "";
let connection = undefined;

const topologyGraph = echarts.init(document.getElementById("topology-graph"));
const packetsPerHostGraph = echarts.init(document.getElementById("number-of-packets-send-per-host"));
const packetsOfLayer4PerHosts = echarts.init(document.getElementById("layer-4"));
const streamTypeCount = echarts.init(document.getElementById("streams-type"));

window.onresize = function () {
    topologyGraph.resize();
    packetsPerHostGraph.resize();
    packetsOfLayer4PerHosts.resize();
    streamTypeCount.resize();
}

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
    src.innerText = `${packet.NetworkLayer.NetworkFlow.Src}:${packet.TransportLayer.TransportFlow.Src}`;
    src.classList.add("blue-text");
    src.style.minWidth = "22%";

    const dst = document.createElement("h3");
    dst.classList.add("red-text");
    dst.innerText = `${packet.NetworkLayer.NetworkFlow.Dst}:${packet.TransportLayer.TransportFlow.Dst}`;
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
    const newTopology = {
        title: {
            text: 'Network Topology',
            top: 'top',
            left: 'left',
        },
        tooltip: {},
        series: [
            {
                name: 'Network Topology',
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
    topologyGraph.setOption(newTopology);
}

async function updateHostPacketCount(data) {
    const newCount = {
        title: {
            text: 'Number of packets per host',
            top: 'top',
            left: 'left',
        },
        tooltip: {},
        toolbox: {
            left: 'right',
            itemSize: 25,
            top: 'top',
            feature: {
                dataZoom: {
                    yAxisIndex: 'none'
                },
            }
        },
        xAxis: {
            type: 'category',
            data: data.Names
        },
        yAxis: {
            type: 'value'
        },
        series: [
            {
                name: 'Number of packets per host',
                data: data.Values,
                type: 'bar',
                showBackground: true,
                backgroundStyle: {
                    color: 'rgba(180, 180, 180, 0.2)'
                }
            }
        ]
    };
    packetsPerHostGraph.setOption(newCount);
}

async function updateLayer4CountGraph(data) {
    const newCount = {
        title: {
            text: 'Layer 4 count',
            top: 'top',
            left: 'left',
        },
        tooltip: {},
        toolbox: {
            left: 'right',
            itemSize: 25,
            top: 'top',
            feature: {
                dataZoom: {
                    yAxisIndex: 'none'
                },
            }
        },
        xAxis: {
            type: 'category',
            data: data.Names
        },
        yAxis: {
            type: 'value'
        },
        series: [
            {
                name: 'Layer 4 Count',
                data: data.Values,
                type: 'bar',
                showBackground: true,
                backgroundStyle: {
                    color: 'rgba(180, 180, 180, 0.2)'
                }
            }
        ]
    };
    packetsOfLayer4PerHosts.setOption(newCount);
}

async function updateStreamTypeCountGraph(data) {
    const newCount = {
        title: {
            text: 'Stream type count',
            top: 'top',
            left: 'left',
        },
        tooltip: {},
        toolbox: {
            left: 'right',
            itemSize: 25,
            top: 'top',
            feature: {
                dataZoom: {
                    yAxisIndex: 'none'
                },
            }
        },
        xAxis: {
            type: 'category',
            data: data.Names
        },
        yAxis: {
            type: 'value'
        },
        series: [
            {
                name: 'Stream type count',
                data: data.Values,
                type: 'bar',
                showBackground: true,
                backgroundStyle: {
                    color: 'rgba(180, 180, 180, 0.2)'
                }
            }
        ]
    };
    streamTypeCount.setOption(newCount);
}

async function updateGraphs(data) {
    switch (data.Target) {
        case "topology":
            updateTopology(data.Options);
            break;
        case "host-packet-count":
            updateHostPacketCount(data.Options);
            break;
        case "layer-4-graph":
            updateLayer4CountGraph(data.Options);
            break;
        case "stream-type-graph":
            updateStreamTypeCountGraph(data.Options);
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


        connection.onmessage = function (message) {
            const data = JSON.parse(message.data);
            if (data.Succeed) {
                connection.onmessage = function (message) {
                    const updateData = JSON.parse(message.data);
                    switch (updateData.Type) {
                        case "packet":
                            loadPacket(updateData.Payload);
                            break;
                        case "stream":
                            loadStream(updateData.Payload);
                            break;
                        case "update-graphs":
                            updateGraphs(updateData.Payload);
                            break;
                    }
                };
            } else {
                document.location.href = "/packet/captures"
            }
        };
    }
}

function stopCapture() {
    connection.send(
        JSON.stringify({
                Action: "STOP",
            }
        )
    );
    document.location.href = "/packet/captures";
}

function selectCaptureInterface(id) {
    document.getElementById("capture").textContent = id;
    selectedInterface = id;
}

function tcpStreamMenu() {
    document.getElementById("tcp-stream-menu").style.display = "block";
    document.getElementById("packet-menu").style.display = "none";
    document.getElementById("data-analysis-menu").style.display = "none";
}

function packetMenu() {
    document.getElementById("packet-menu").style.display = "block";
    document.getElementById("tcp-stream-menu").style.display = "none";
    document.getElementById("data-analysis-menu").style.display = "none";
}

function dataAnalysisMenu() {
    document.getElementById("data-analysis-menu").style.display = "block";
    document.getElementById("packet-menu").style.display = "none";
    document.getElementById("tcp-stream-menu").style.display = "none";
}

function detailsMenu() {
    document.getElementById("data-analysis-menu").style.display = "none";
    document.getElementById("packet-menu").style.display = "none";
    document.getElementById("tcp-stream-menu").style.display = "none";
    document.getElementById("details-menu").style.display = "block";
}