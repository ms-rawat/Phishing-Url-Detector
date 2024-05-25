document.addEventListener('DOMContentLoaded', function () {
    const predictionResult = document.getElementById('predictionResult');
    const signal = document.getElementById('signal');
    const h4 = document.getElementsByTagName('h4')[0];
    const status = document.getElementById('status');

    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        const url = tabs[0].url;
        if (url) {
            chrome.runtime.sendMessage({ action: 'predict', url: url }, function (response) {
                try {
                    console.log(response);
                    const prediction = response.prediction[0];
                    const probability = response.probability[0][1];
                    const percentage = Math.round(probability * 100);


                    if (percentage > 50) {
                        signal.style.backgroundColor = 'green';
                    } else {
                        signal.style.backgroundColor = 'red';
                    }


                    predictionResult.innerHTML = `Probability: ${prediction}, Prediction : ${percentage}% safe to use`;
                    h4.style.display = 'none';
                } catch (error) {
                    console.error('Error processing prediction response:', error);
                    predictionResult.innerHTML = 'Error processing prediction.';
                    signal.style.backgroundColor = 'gray'; // Set a neutral color for error
                    h4.style.display = 'block'; // Show h4 element to indicate an error
                }
            });
        }
    });
});
