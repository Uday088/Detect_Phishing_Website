import re
import whois

def category2(website):
        
    file_obj = open(r'D:\MTECH\Theory\information security\J-Component\Detect_Phishing_Website\sample.txt','a')

#8 By accessing the whois site the Domain Registration is fetched for the URL
    page = whois.whois(website)
    if type(page.expiration_date) == list:
        domain_reg_len = (page.expiration_date[0] - page.creation_date[0]).days
    else:
        domain_reg_len = (page.expiration_date - page.creation_date).days
    #print(domain_reg_len)
    if domain_reg_len <= 365:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')

# Verifying the Non-Standard Port
    match_port = re.search(':[//]+[a-z]+.[a-z0-9A-Z]+.[a-zA-Z]+:([0-9#]*)',website)
    if match_port:
        print (match_port.group())
        if match_port.group(1) == '#':
            file_obj.write('-1,')
        else:
            file_obj.write('1,')
    else:
        file_obj.write('1,')
    file_obj.close()


