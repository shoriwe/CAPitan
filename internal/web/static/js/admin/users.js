function createUsername() {
    const username = document.getElementById("username").value;
    const formBody = [];
    formBody.push("username=" + encodeURIComponent(username));
    fetch(
        "/admin/user?action=new-user",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formBody.join("&")
        }
    ).then(_ => {
        window.location.href = window.location.href
    });
    return false;
}

function checkUsername() {
    fetch("/admin/user?action=test-user", {
        method: "POST",
        body: JSON.stringify({Username: document.getElementById("username").value}),
        headers: {
            'Content-Type': 'application/json'
        }
    }).then(response => {
            response.json().then(data => {
                    if (data.Found) {
                        document.getElementById("user-already-taken").style.display = "block";
                        document.getElementById("user-not-taken").style.display = "none";
                    } else {
                        document.getElementById("user-already-taken").style.display = "none";
                        document.getElementById("user-not-taken").style.display = "block";
                    }
                }
            );
        }
    );
}

function showDialog() {
    document.getElementById("new-user-dialog").style.display = "block";
}

function hideDialog() {
    document.getElementById("new-user-dialog").style.display = "none";
}