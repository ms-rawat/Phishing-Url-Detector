


## Installation

setup project by following below instructions

```bash
clone the repo  git clone `https://github.com/ms-rawat/Phishing-Url-Detector`
cd Phishing-Url-Detector
```
Create and Activate a Virtual Environment
* on macOS/linux
```bash
python3 -m venv sklearn-venv
source sklearn-venv/bin/activate
```
* on windows
```bash
python -m venv sklearn-venv
sklearn-venv\Scripts\
```

## install dependies
Install the required dependencies using the `requirements.txt` file
```bash
pip install -r requirements.txt
```
## Directory Tree 
```
├── extensioncode  
├── sklearn-venv
├── .gitignore
├── app.py
├── feature.py
├── model.pkl
├── model.py
├── phishing.csv
├── README.md
├── requirements.txt
├── test.py
├── training.py

## Loading a Chrome Extension from Your Computer

#### Prerequisites
+ Ensure that you have Google Chrome installed on your computer.
+ Ensure that you have the extension files available on your computer.
#### Instructions
+ Open Chrome Browser:
+ Launch the Google Chrome browser on your computer.

+ Access the Extensions Page:
+ In the Chrome address bar, type ``chrome://extensions/`` and press Enter. This will take you to the Extensions page.

+ Enable Developer Mode:
  In the top right corner of the Extensions page, you will see a    toggle switch labeled "Developer mode". Turn this switch on.

+ Load Unpacked Extension:
  Once Developer mode is enabled, you will see three new buttons at the top of the page: "Load unpacked", "Pack extension", and "Update".

+ Click on the "Load unpacked" button.
  Select Extension Folder in cloned repo and click ok


+ After selecting the folder, the extension should appear on the Extensions page. You should see your extension listed with its name  `phishing website detector`, icon, and a description.

+ Activate the Extension:
  Ensure the extension is enabled (the toggle switch should be blue). and don't forgot to pin the extension.


## Running the project
after activating and loading the extension in browser

run the `python app.py` to start backend server know you can click on extension and wait ,The extension will fetch the current URL in the browser and provide information about its authenticity.








## Conclusion
1. The final take away form this project is to explore various machine learning models, perform Exploratory Data Analysis on phishing dataset and understanding their features. 
2. Creating this notebook helped me to learn a lot about the features affecting the models to detect whether URL is safe or not, also I came to know how to tuned model and how they affect the model performance.
3. The final conclusion on the Phishing dataset is that the some feature like "HTTTPS", "AnchorURL", "WebsiteTraffic" have more importance to classify URL is phishing URL or not. 
4. Gradient Boosting Classifier currectly classify URL upto 97.4% respective classes and hence reduces the chance of malicious attachments.


### sample phishing websites
1.https://bryzekcpa-pdf.pages.dev/
2.https://israel-hamas24newsclipsupdates.vercel.app/
