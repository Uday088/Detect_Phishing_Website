import re

#1.Checking whether the URL has IP address instead of DNS name

def category1(url):
        
    match = re.search('[0-9]{1,3}[.]+?[0-9]{1,3}[.]+?[0-9]{0,3}[.]+?[0-9]{1,3}',url)
    file_obj = open(r'D:\MTECH\Theory\information security\J-Component\Detect_Phishing_Website\sample.txt','w')
    if match!=None:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')

#2. Checking the url_length to find the legitimate URL length.
    if len(url)<54:
        file_obj.write('1,')
    elif len(url)<=75 and len(url)>=54:
        file_obj.write('0,')
    else:
        file_obj.write('-1,')

#3.Filtering whether it Tiny_url-a suspicious/phishing URL
    if len(url)<22:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')

#4. Checking for '@'_matching character in the URL
    at_match = re.search('[@]+?',url)
    if at_match != None:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')

#5. Checking the character '//'in the URL
    dble_slash_match = re.findall('//',url)
    if len(dble_slash_match)>1:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')

#6. Checking the character '-' in the URL
    dash_match = re.search('-',url)
    if dash_match:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')

#7.Checking the 'https-' parameter in the URL
    https_match = re.search('https-',url)
    if https_match:
        file_obj.write('-1,')
    else:
        file_obj.write('1,')
    
    file_obj.close()
