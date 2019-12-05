/**
 * ----------------------------------------------------------------------------------------------
 * ------------------------------------ Handle forms with js ------------------------------------
 * --------------- taken from https://lengstorf.com/code/get-form-values-as-json/ ---------------
 * ----------------------------------------------------------------------------------------------
 */

/**
 * Checks that an element has a non-empty `name` and `value` property.
 * @param  {Element} element  the element to check
 * @return {Bool}             true if the element is an input, false if not
 */
const isValidElement = element => {
    return element.name && element.value;
};

/**
 * Checks if an element’s value can be saved (e.g. not an unselected checkbox).
 * @param  {Element} element  the element to check
 * @return {Boolean}          true if the value should be added, false if not
 */
const isValidValue = element => {
    return !["checkbox", "radio"].includes(element.type) || element.checked;
};

/**
 * Checks if an input is a checkbox, because checkboxes allow multiple values.
 * @param  {Element} element  the element to check
 * @return {Boolean}          true if the element is a checkbox, false if not
 */
const isCheckbox = element => element.type === "checkbox";

/**
 * Checks if an input is a `select` with the `multiple` attribute.
 * @param  {Element} element  the element to check
 * @return {Boolean}          true if the element is a multiselect, false if not
 */
const isMultiSelect = element => element.options && element.multiple;

/**
 * Retrieves the selected options from a multi-select as an array.
 * @param  {HTMLOptionsCollection} options  the options for the select
 * @return {Array}                          an array of selected option values
 */
const getSelectValues = options =>
    [].reduce.call(
        options,
        (values, option) => {
            return option.selected ? values.concat(option.value) : values;
        },
        []
    );

/**
 * Retrieves input data from a form and returns it as a JSON object.
 * @param  {HTMLFormControlsCollection} elements  the form elements
 * @return {Object}                               form data as an object literal
 */
const formToJSON = elements =>
    [].reduce.call(
        elements,
        (data, element) => {
            // Make sure the element has the required properties and should be added.
            if (isValidElement(element) && isValidValue(element)) {
                /*
                 * Some fields allow for more than one value, so we need to check if this
                 * is one of those fields and, if so, store the values as an array.
                 */
                if (isCheckbox(element)) {
                    data[element.name] = (data[element.name] || []).concat(
                        element.value
                    );
                } else if (isMultiSelect(element)) {
                    data[element.name] = getSelectValues(element);
                } else {
                    data[element.name] = element.value;
                }
            }

            return data;
        },
        {}
    );

/**
 * ----------------------------------------------------------------------------------------------
 */

// addEventListener support for IE8
function bindEvent(element, eventName, eventHandler) {
    if (element.addEventListener) {
        element.addEventListener(eventName, eventHandler, false);
    } else if (element.attachEvent) {
        element.attachEvent("on" + eventName, eventHandler);
    }
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

// Sends text request to server via POST request
function postReq(path, textReq, responseCallback = null) {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = () => {
        if (xhr.readyState == 4 && xhr.status == 200) {
            if (responseCallback !== null) responseCallback(xhr);
        }
    };
    xhr.open("POST", path, true);
    xhr.send(textReq);
}

// Sends text request to server via GET request
function getReq(path, responseCallback = null) {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = () => {
        if (xhr.readyState == 4 && xhr.status == 200) {
            if (responseCallback !== null) responseCallback(xhr);
        }
    };
    xhr.open("GET", path, true);
    xhr.send();
}

// Create the iframe
var iframeSource = "http://127.0.0.1:3500/user.html";
var iframe = document.createElement("iframe");
iframe.setAttribute("src", iframeSource);
iframe.setAttribute("id", "cred_iframe");
iframe.setAttribute("hidden", "true");

// See: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#Attributes
iframe.setAttribute("sandbox", "allow-scripts allow-modals allow-same-origin");

document.body.appendChild(iframe);

var iframeEl = document.getElementById("cred_iframe"),
    results = document.getElementById("results");

// Send a message to the child iframe
function sendMessage(msg, dest = "*") {
    // Make sure you are sending a string, and to stringify JSON
    iframeEl.contentWindow.postMessage(msg, dest);
}

// write message to page
function writeToPage(msg) {
    results.innerHTML = msg;
}

// Issuer
// Message handler - implements protocol for communicating with credential iframe
var issuerMessageHandler = msgEvent => {
    console.log("ISSUER: received message from " + msgEvent.origin);
    console.log("ISSUER: " + msgEvent.data);

    let elements = msgEvent.data.split(";");
    const command = elements.shift();
    const content = elements.join(";");

    if (command === "startissue") {
        postReq("/issue", content, responseObj => {
            sendMessage("issue;" + responseObj.response);
        });
        return;
    }

    if (command === "issue" && content === "success") {
        writeToPage(
            "Credential successfully issued! You can close this window now."
        );
        return;
    }

    if (command === "issue" && content === "fail") {
        writeToPage("There was a problem issuing your credential.");
        return;
    }

    console.log(
        "ISSUER: I do not understand message from " + msgEvent.origin + "..."
    );
};

// Tool
// Message handler - implements protocol for communicating with credential iframe
var toolMessageHandler = msgEvent => {
    console.log("TOOL: received message from " + msgEvent.origin);
    console.log("TOOL: " + msgEvent.data);

    let elements = msgEvent.data.split(";");
    const command = elements.shift();
    const content = elements.join(";");

    if (command === "show") {
        if (content === "noshow") {
            writeToPage(
                "You cannot use the tool if you do not show your credential..."
            );
        } else if (!content) {
            writeToPage(
                "You need to get a credential first before accessing this tool"
            );
        } else {
            postObj("/show", JSON.parse(content), xhr => {
                if (xhr.response === "true") {
                    writeToPage("Credential is valid! You can use the tool.");
                } else {
                    writeToPage("Your credential is not valid...");
                }
            });
        }

        return;
    }

    if (command === "provenym") {
        const form = document.getElementById(FORM_ID);
        const data = formToJSON(form.elements);
        data.nymData = content;
        console.log("Data from form");
        console.log(data);

        // post data to Tool server
        postObj("http://127.0.0.1:3002/result", data, response => {
            window.location.href = "http://127.0.0.1:3002/list";
        });

        return;
    }

    console.log("TOOL: I do not understand this message...");
};

/**
 * A handler function to prevent default submission and run our custom script.
 * @param  {Event} event  the submit event triggered by the user
 * @return {void}
 */
// const handleFormSubmit = questID => event => {
//     // Stop the form from submitting since we’re handling that with AJAX.
//     event.preventDefault();

//     sendMessage("provenym;" + questID);
// };

// QS
/**
 * A handler function to prevent default submission and run our custom script.
 * @param  {Event} event  the submit event triggered by the user
 * @return {void}
 */
const handleFormSubmit = (formID, reFormID, questID) => event => {
    // Stop the form from submitting since we’re handling that with AJAX/lightnion
    event.preventDefault();

    const answer = {};

    const form = document.getElementById(formID);
    const re_form = document.getElementById(reFormID);
    const answerObj = formToJSON(form.elements);
    answer.answerObj = answerObj;

    const studyIDs = formToJSON(re_form.elements)["studies"];
    answer.studyIDs = studyIDs;
    answer.questID = questID;
    const answerStr = JSON.stringify(answer);

    sendMessage("answer;" + answerStr);
};

// Message handler for questionnaire pages
var questMessageHandler = (formID, questID) => msgEvent => {
    console.log("QUEST: received message from " + msgEvent.origin);
    console.log("QUEST: " + msgEvent.data);

    let elements = msgEvent.data.split(";");
    const command = elements.shift();
    const content = elements.join(";");

    if (command === "provenym") {
        const form = document.getElementById(formID);
        const data = formToJSON(form.elements);
        data.nymData = content;

        // post data to QS server
        postObj("http://127.0.0.1:3002/result/" + questID, data, response => {
            window.location.href = "http://127.0.0.1:3002/list/" + questID;
        });

        return;
    }

    console.log("QUEST: I do not understand this message...");
};

function sendtoken(studyID) {
    sendMessage("token;" + studyID);
}
