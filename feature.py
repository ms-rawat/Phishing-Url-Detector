import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    features = []

    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1. UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2. longUrl
    def longUrl(self):
        if len(self.domain) < 54:
            return 1
        elif len(self.domain) >= 54 and len(self.domain) <= 75:
            return 0
        else:
            return -1

    # 3. shortUrl
    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
                          self.url)
        if match:
            return -1
        return 1

    # 4. Symbol@
    def symbol(self):
        if '@' in self.url:
            return -1
        return 1

    # 5. Redirecting//
    def redirecting(self):
        if self.url.count('//') > 6:
            return -1
        return 1

    # 6. prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall('-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1

    # 7. SubDomains
    def SubDomains(self):
        dot_count = self.domain.count('.')
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8. HTTPS
    def Hppts(self):
        try:
            if 'https' in self.urlparse.scheme:
                return 1
            return -1
        except:
            return 1

    # 9. DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date

            if len(expiration_date) > 0 and len(creation_date) > 0:
                age = (expiration_date[0] - creation_date[0]).days // 30
                if age >= 12:
                    return 1
            return -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for link in head.find_all('link', href=True):
                    dots = link['href'].count('.')
                    if self.url in link['href'] or dots == 1 or self.domain in link['href']:
                        return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.urlparse.scheme:
                return -1
            return 1
        except:
            return -1

    # 13. RequestURL
    def RequestURL(self):
        try:
            success, i = 0, 0

            for tag in ['img', 'audio', 'embed', 'iframe']:
                for item in self.soup.find_all(tag, src=True):
                    dots = item['src'].count('.')
                    if self.url in item['src'] or self.domain in item['src'] or dots == 1:
                        success += 1
                    i += 1

            percentage = (success / i) * 100 if i != 0 else 0
            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            else:
                return -1
        except:
            return -1

    # 14. AnchorURL
    def AnchorURL(self):
        try:
            unsafe, i = 0, 0
            for a in self.soup.find_all('a', href=True):
                href = a['href']
                if '#' in href or href.lower().startswith("javascript") or href.lower().startswith("mailto") or not (self.url in href or self.domain in href):
                    unsafe += 1
                i += 1

            percentage = (unsafe / i) * 100 if i != 0 else 0
            if percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            else:
                return -1
        except:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            success, i = 0, 0
            for tag in ['link', 'script']:
                for item in self.soup.find_all(tag, href=True):
                    dots = item['href'].count('.')
                    if self.url in item['href'] or self.domain in item['href'] or dots == 1:
                        success += 1
                    i += 1

            percentage = (success / i) * 100 if i != 0 else 0
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            else:
                return -1
        except:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True)) == 0:
                return 1
            else:
                for form in self.soup.find_all('form', action=True):
                    action = form['action']
                    if action == "" or action == "about:blank":
                        return -1
                    elif self.url not in action and self.domain not in action:
                        return 0
                    else:
                        return 1
        except:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soup.text):
                return -1
            else:
                return 1
        except:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response.text:
                return 1
            else:
                return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif 1 < len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if re.findall(r"<iframe>|<frameBorder>", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            if creation_date:
                creation_date = creation_date[0]
                today = date.today()
                age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
                if age >= 6:
                    return 1
            return -1
        except:
            return -1

    # 25. DNSRecording
    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date
            if creation_date:
                creation_date = creation_date[0]
                today = date.today()
                age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
                if age >= 6:
                    return 1
            return -1
        except:
            return -1

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(),
                                  "xml").find("REACH")['RANK']
            if int(rank) < 100000:
                return 1
            return 0
        except:
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", prank_checker_response.text)[0])
            if 0 < global_rank < 100000:
                return 1
            return -1
        except:
            return -1

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return 1
            else:
                return -1
        except:
            return 1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif 0 < number_of_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
                'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|'
                '96\.lt|ow\.ly|awardspace\.com|hol\.es|sweddy\.com|myjino\.ru|96\.lt|bit\.ly|2fh\.co|000webhost\.com|'
                '6te\.net|twomini\.com|jimdo\.com|000space\.com|weebly\.com|3eeweb\.com|fr\.gd|tl\.gd|tr\.gg|wix\.com|'
                'weebly\.com|myjino\.ru|000webhost\.com|uhostfull\.com|wink\.ws|is-great\.net|16mb\.com|loxblog\.com|'
                'blogspot\.com|wordpress\.com|freeoda\.com|blogspot\.com|hostinger\.com|heroku\.com|'
                'bitbucket\.org|pythonanywhere\.com|aws\.com|azurewebsites\.net|000webhostapp\.com|'
                'azurewebsites\.net|bitballoon\.com|netlify\.com|surge\.sh|github\.io|webflow\.com|strikingly\.com|'
                'pages\.dev|firebaseapp\.com|dudaone\.com|launchrock\.com|tilda\.ws|elementor\.com|'
                'carrd\.co|simplebooklet\.com|weebly\.com|strikingly\.com|edublogs\.org|site\.co\.uk|'
                'weebly\.com|hatenadiary\.com|hateblo\.jp|yolasite\.com|webnode\.com|jimdosite\.com|squarespace\.com|'
                'webnode\.com|ucraft\.net|snack\.ws|bubbleapps\.io|ucraft\.me|simdif\.com|breezi\.com|ucoz\.com|'
                'smore\.com|eklablog\.com|ontrapages\.com|shopify\.com|blogspot\.com|joomla\.com|wpengine\.com|'
                'ning\.com|bigcartel\.com|simplero\.com|lightbox\.com|page\.tl|ukit\.com|sitey\.com|tilda\.cc|'
                'ampblogs\.com|1msite\.com|1freehosting\.com|www1\.cloudns\.com|hatena\.ne\.jp|biz\.n\.fukushima\.jp|'
                'orbi\.to|biz\.l\.to|info\.com\.hokkaido\.to|ac\.gibier\.n\.to|ed\.a\.ishikawa\.jp|neko\.amimono\.nara\.jp|'
                'miyako\.nara\.jp|phpnet\.us|ne\.jpn\.com|gr8\.jp|jsf\.togichi\.jp|ed\.tokushima\.jp|lib\.yamagata\.jp|'
                'or\.m\.ishikawa\.jp|miyazaki\.m\.miyazaki\.jp|oita\.oita\.lg\.jp|cloudaccess\.net|cesidian\.xyz|w3\.to|'
                '000webhostapp\.com|000webhost\.app|000web\.host|cy\.cam|gu\.gl|my-gg\.ga|my-fast\.ga|my-dd\.tk|jdevcloud\.com',
                self.url)
            if url_match:
                return -1
            else:
                return 1
        except:
            return -1


if __name__ == "__main__":
    url = input("Enter URL: ")
    obj = FeatureExtraction(url)
    print(obj.features)
