"use strict";

// addEventListener support for IE8
function bindEvent(element, eventName, eventHandler) {
    if (element.addEventListener) {
        element.addEventListener(eventName, eventHandler, false);
    } else if (element.attachEvent) {
        element.attachEvent('on' + eventName, eventHandler);
    }
}

// Send a message to the parent
function sendMessage (msg, dest="*") {
    // Make sure you are sending a string, and to stringify JSON
    window.parent.postMessage(msg, dest);
}

// Sends object to server via POST request
function postObj(path, obj, responseCallback = null) {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = () => {
        if (xhr.readyState == 4 && xhr.status == 200) {
            if (responseCallback !== null) responseCallback(xhr);
        }
    };
    xhr.open("POST", path, true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.send(JSON.stringify(obj));
}

// Handling messages coming to iframe from parent
async function messageHandler(msgEvent) {
    console.log("USER CREDENTIALS: received message from " + msgEvent.origin);
    console.log("USER CREDENTIALS: " + msgEvent.data);

    let elements = msgEvent.data.split(";");
    const command = elements.shift();
    const content = elements.join(";");

    if (command === "startissue") {
        await userHelper.setup();
        sendMessage("startissue;" + userHelper.commit(content));
        return;
    }

    if (command === "issue") {
        if (confirm("Do you want to store the credential issued by " + msgEvent.origin + "?")) {
            const sigAndAttrs = JSON.parse(content);
            if (userHelper.unblindAndStore(sigAndAttrs)) {
                sendMessage("issue;success");
                return;
            }
        }
        sendMessage("issue;fail");
        return;
    }

    if (command === "show") {
        await userHelper.setup();
        if (confirm("Do you want to show your credential to " + msgEvent.origin + "?")) {
            sendMessage("show;" + userHelper.show());
        } else {
            sendMessage("show;noshow");
        }
        return;
    }

    if (command === "provenym") {
        await userHelper.setup();
        sendMessage("provenym;" + userHelper.showWithNym(content));
        return;
    }

    if (command === "answer") {
        console.log("USER CREDENTIALS: Received a request to sign an answer.");
        await userHelper.setupQ();
        var answerData = JSON.parse(content);

        console.log("USER CREDENTIALS: answerData");
        console.log(answerData);

        // sign answer including adding linking info
        var answer = userHelper.answerQuest(answerData);

        // post data to QS server - TODO replace with lightnion to send answer over Tor
        postObj("http://127.0.0.1:3002/result/" + answerData.questID, answer, response => {
            // window.location.href = "http://127.0.0.1:3002/list/" + questID;
            console.log("USER CREDENTIALS: got response from QS");
            console.log(response);
        });
        return;
    }

    if (command === "token") {
        console.log("USER CREDENTIALS: Received a request to send linking token.");
        await userHelper.setupQ();

        const studyID = content;
        const url = "http://127.0.0.1:3002/token/" + studyID;

        if (!confirm("Are you sure you want to send the token concerning " + studyID + "?"))
            return;

        const tokenStr = userHelper.getStrToken(studyID);

        // post token to QS server - TODO replace with lightnion to send answer over Tor
        postObj(url, {tokenStr: tokenStr}, response => {
            // window.location.href = "http://127.0.0.1:3002/list/" + questID;
            console.log("USER CREDENTIALS: got response from QS");
            console.log(response);
        });

        return;
    }

    console.log("USER CREDENTIALS: I do not understand message from parent...");
}

// Listen to messages from parent window
bindEvent(window, 'message', messageHandler);
