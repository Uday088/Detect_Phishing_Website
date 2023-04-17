import whois
import re
from bs4 import BeautifulSoup
import urllib.request


def category4(website):
        
    file_obj = open(r'D:\MTECH\Theory\information security\J-Component\Detect_Phishing_Website\sample.txt','a')

#15 Fetching the Age of Domain from whois site
    
    whois_page = whois.whois(website)
    if whois_page:
        if type(whois_page.expiration_date) == list:
            if len(whois_page.expiration_date) > 1 and len(whois_page.creation_date) > 1:
                age_of_domain = (whois_page.expiration_date[0] - whois_page.creation_date[0]).days
        else:
            age_of_domain = (whois_page.expiration_date - whois_page.creation_date).days
            if age_of_domain >= 182:
                file_obj.write('1,')
            else:
                file_obj.write('-1,')
#16 For DNS Record
        file_obj.write('1,')
    else:
            file_obj.write('-1,')
        
#17 For Statistical-Reports Based Feature extraction
    if type(whois_page.domain_name) == list:
        host_name = whois_page.domain_name[0].lower()
    elif type(whois_page.domain_name) == str:
        host_name = whois_page.domain_name.lower()
    
    page = urllib.request.urlopen('https://www.phishtank.com/phish_search.php?verified=u&active=y')
    soup = BeautifulSoup(page,'html.parser')

    tds = soup.findAll('td',{'class':'value'})
    for val in tds:
        match_link = re.search('([http]*[https]*:[-/?.a-z0-9A-Z]+)',str(val))
        if match_link:
            match_host_name = re.search(host_name,match_link.group())
            if match_host_name:
                file_obj.write('-1,')
                break
            else:
                file_obj.write('1,')
                break
    file_obj.close()
