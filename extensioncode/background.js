// background.js

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.action === "predict") {
        fetch('http://localhost:5000/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: message.url })
        })
            .then(response => response.json())
            .then(data => sendResponse(data))
            .catch(error => console.error('Error:', error));
        return true; // Needed to indicate that sendResponse will be called asynchronously
    }
});
