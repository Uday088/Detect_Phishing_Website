from bs4 import BeautifulSoup
import re
import urllib.request
import whois


def category3(website):
        
    file_obj = open(r'D:\MTECH\Theory\information security\J-Component\Detect_Phishing_Website\sample.txt','a')
    file_obj.closed
    match_web = re.search('(.[\w]+[-`]*.com)',website)
    if match_web:
        domain= match_web.group(1)
    
    page = urllib.request.urlopen(website)
    soup = BeautifulSoup(page,"html.parser")
    dict_anchor = {'hashvalue':0,'content':0,'jvalue':0,'anyo':0}
    dict_url = {'phishing':0,'legitimate':0}
    for data in soup.findAll('a'):
#10 Requests URL checking
        if data.get('href'):
            match_url = re.search('^http',str(data.get('href')))
            if match_url:
                if 'phishing' in dict_url:
                    dict_url['phishing'] +=1
                else:
                    dict_url['phishing'] = 0

            else:
                if 'legitimate' in dict_url:
                    dict_url['legitimate'] +=1
                else:
                    dict_url['legitimate'] = 0
#11 URL OF ANCHOR checking
        if data.get('href'):
            match = re.search('^#$',str(data.get('href')))
            if match:
                if 'hashvalue' in dict_anchor:
                    dict_anchor['hashvalue'] += 1
                else:
                    dict_anchor['hashvalue'] = 0
            match2 = re.search('^#[a-zA-Z0-9]+$',str(data.get('href')),re.I)
            if match2:
                if 'content' in dict_anchor:
                    dict_anchor['content'] +=1
                else:
                    dict_anchor['content'] = 0
            match3 = re.search('^JavaScript::void(0)',str(data.get('href')),re.I)
            if match3:
                if 'jvalue' in dict_anchor:
                    dict_anchor['jvalue'] +=1
                else:
                    dict_anchor['jvalue'] = 0
            match4 = re.search('[0-9a-zA-Z/]+',str(data.get('href')),re.I)
            if match4:
                if 'anyo' in dict_anchor:
                    dict_anchor['anyo'] += 1
                else:
                    dict_anchor['anyo'] = 0
    phishing = dict_anchor['hashvalue']+dict_anchor['content']+dict_anchor['jvalue']
    total = dict_anchor['hashvalue']+dict_anchor['content']+dict_anchor['jvalue']+dict_anchor['anyo']
    if  total != 0:
        total_phishing_per = float(phishing*100/total)
    else:
        total_phishing_per = None
    total_requested_url = dict_url['phishing']+dict_url['legitimate']
    if total_requested_url != 0:
        total_phishing_url_per = float(dict_url['phishing']*100/total_requested_url)
    else:
        total_phishing_url_per = None
    
#12 Verifying the Links in Meta, Script and Link tags
    meta = soup.findAll('meta')
    script = soup.findAll('script')
    link = soup.findAll('link')
    dict_MSL = {'L_meta':len(meta),'P_link':0,'L_script':0,'L_link':0,'P_script':0}
    for val in link:
        if val.get('href') != None:
            match_link1 = re.search('^[/#]+',str(val.get('href')))
            if match_link1:
                if 'L_link' in dict_MSL:
                        dict_MSL['L_link'] += 1
            else:
                match_link2 = re.search('.css$',str(val.get('href')))
                if match_link2:
                    if 'L_link' in dict_MSL:
                        dict_MSL['L_link'] += 1
                else:
                    match_link3 = re.search('([\w]+.[\w]+[-`a-z0-9A-Z]*.com)',str(val.get('href')))
                    if match_link3:
                        modified_url = re.search('(.[\w]+[-`a-z0-9A-Z]*.com)',match_link3.group(1))
                        if domain == modified_url.group(1):
                            if 'L_link' in dict_MSL:
                                dict_MSL['L_link'] += 1
                        else:
                            if 'P_link' in dict_MSL:
                                dict_MSL['P_link'] += 1
                    else:
                        if 'P_link' in dict_MSL:
                            dict_MSL['P_link'] += 1
    for val in script:
        if val.get('src') != None:
            match_script1 = re.search('.js$',str(val.get('src')))
            if match_script1:
                if 'L_script' in dict_MSL:
                    dict_MSL['L_script'] += 1
            elif re.search('.com$',str(val.get('src'))):
                match_script2 = re.search('(www.[\w]+[-`\w]*.com$)',str(val.get('src')))
                match_script2 = re.search('(.[\w]+[-`a-z0-9A-Z]*.com)',match_script2.group(1))
                if match_script2.group(1) == domain:
                    if 'L_script' in dict_MSL:
                        dict_MSL['L_script'] += 1
                else:
                    if 'P_script' in dict_MSL:
                        dict_MSL['P_script'] += 1
            else:
                if 'P_script' in dict_MSL:
                    dict_MSL['P_script'] += 1
    total_MSL = sum(dict_MSL.values())
    P_MSL = dict_MSL['P_script']+dict_MSL['P_link']
    if total_MSL != 0:
        per_p_msl = float(P_MSL*100/total_MSL)
    else:
        per_p_msl = None

#13 Requesting URL to write on the sample file
    if total_phishing_url_per != None:
        if total_phishing_url_per < 22  :
            file_obj.write('1,')
        else:
            file_obj.write('-1,')
    else:
        file_obj.write('-1,')
    file_obj.flush()

#14 URL of Anchor write on file : output
    if total_phishing_per != None:
        if total_phishing_per < 31 :
            file_obj.write('1,')
        elif total_phishing_per >= 31 and total_phishing_per < 67 or total_phishing_per != None:
            file_obj.write('0,')
        else:
            file_obj.write('-1,')
    else:
        file_obj.write('-1,')
    file_obj.flush()
    #write MSL output on file
    if per_p_msl != None:
        if per_p_msl < 17 :
            file_obj.write('1,')
        elif per_p_msl >= 17 and per_p_msl < 81 or per_p_msl != None:
            file_obj.write('0,')
        else:
            file_obj.write('-1,')
    else:
        file_obj.write('-1,')
    file_obj.flush()
    
#15 Server Form Handler (SFH)
    
    form = soup.find('form')
    if form != None:
        if form.get('action') != None:
            match_form = re.search('^[./]+',str(form.get('action')))
            if match_form:
                file_obj.write('1,')
            elif re.search('^http',str(form.get('action'))):
                match_form2 = re.search('(www.[a-z0-9A-Z]+[-`]*.com)',str(form.get('action')))
                if match_form2:
                    modified_url = re.search('(.[\w]+[-`a-z0-9A-Z]*.com)',match_form2.group(1))
                    if domain == modified_url.group(1):
                        file_obj.write('1,')
                    else:
                        file_obj.write('0,')
            else:
                file_obj.write('-1,')
        else:
            file_obj.write('1,')
    else:
        file_obj.write('0,')
    file_obj.flush()
#16 Verifying any Abnormal URL
    temp = whois.whois(website)
    if type(temp.domain_name) == list:
        domain_name = temp.domain_name[0].lower()
    elif type(temp.domain_name) == str:
        domain_name = temp.domain_name.lower()
    match_d_name = re.search(domain_name,website)
    if match_d_name:
        file_obj.write('1,')
    else:
        file_obj.write('-1,')
    file_obj.flush()
        
            
    file_obj.close()

        
        
