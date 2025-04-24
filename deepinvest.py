import requests
import sys
import urllib3
import re 
from termcolor import colored
print(colored("""
######## ##     ## ########    ########  ######## ######## ########  #### ##    ## ##     ## ########  ######  ######## 
   ##    ##     ## ##          ##     ## ##       ##       ##     ##  ##  ###   ## ##     ## ##       ##    ##    ##    
   ##    ##     ## ##          ##     ## ##       ##       ##     ##  ##  ####  ## ##     ## ##       ##          ##    
   ##    ######### ######      ##     ## ######   ######   ########   ##  ## ## ## ##     ## ######    ######     ##    
   ##    ##     ## ##          ##     ## ##       ##       ##         ##  ##  ####  ##   ##  ##             ##    ##    
   ##    ##     ## ##          ##     ## ##       ##       ##         ##  ##   ###   ## ##   ##       ##    ##    ##    
   ##    ##     ## ########    ########  ######## ######## ##        #### ##    ##    ###    ########  ######     ## 
""", "blue"))
print(colored("""
    Created By: @daxilox
""", "red"))
 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urlArgument = sys.argv[1]
url_format = r'https?:\/\/(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:\/[^\s"\'<>]*)*'
comments_format = r'<!--.*?-->'
if re.fullmatch(url_format, urlArgument):
    getrequest = requests.get(urlArgument, verify=False)
elif sys.argv[1] == '-h' or sys.argv[1] == '--help':
    print(colored("""
          Use example: python deepinvest.py http://example.com
          If you're performing a legal penetration test, it’s better to use:
                                "proxychains python deepinvest.py http://example.com"
            help:
                -o : output file
                -h : for help""", "red"))
    sys.exit()
else:
        print(colored(f"""
          Uknown argument "{sys.argv[1]}" 
          Use example: python deepinvest.py http://example.com
          If you're performing a legal penetration test, it’s better to use:
                                "proxychains python deepinvest.py http://example.com"
            help:
                -o : output file
                -h : for help""", "red"))
        sys.exit()
sourcecode = getrequest.text
def get_urls():
    founded_urls_that_may_duplicate = re.findall(url_format, sourcecode)
    founded_urls = []
    for url in founded_urls_that_may_duplicate:
        if url not in founded_urls and f"{url}/" not in founded_urls:
            founded_urls.append(url)
    return founded_urls
def infos_from_response_header():
    response_header = getrequest.headers
    array_of_interesting_headers = ['Server','X-Powered-By','Set-Cookie','Strict-Transport-Security','Content-Security-Policy','X-Frame-Options','X-Content-Type-Options','Referrer-Policy','Access-Control-Allow-Origin','Location','WWW-Authenticate','Cache-Control','ETag','Via','Public-Key-Pins','X-XSS-Protection']
    for header in array_of_interesting_headers:
        if header in response_header:
            print(colored(f"{header}", "red")+colored(f":{response_header[header]}", "green"))

def http_methods_supported_by_The_website():
    url = urlArgument
    http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'TRACE', 'CONNECT', 'PATCH']
    url_options_method = requests.options(url, verify=False)
    if url_options_method.status_code == 200 and 'Allow' in url_options_method.headers == True:
        print(colored("OPTIONS: ", "red")+colored(url_options_method.headers['Allow'], "green"))
    else:
        print(colored("OPTIONS: ", "red")+colored("Not allowed", "blue"))
        for http_method in http_methods:
            url_http_method_request = requests.request(http_method, url, verify=False)
            if url_http_method_request.status_code == 200:
                print(colored(f"{http_method}: ", "red")+colored("Allowed","green"))
            else:
                print(colored(f"{http_method}: ", "red")+colored("Not allowed","blue"))

def check_for_most_known_hidden_directories():
    most_known_hidden_dirs = ['/.git/', '/.env/', '/admin/', '/backup/', '/backups', '/old/', '/robots.txt', '/test/', '/dev/', '/logs/', '/config/', '/conf/', '/private/', '/secret/', '/uploads/', '/files/', '/cgi-bin/']
    url = urlArgument
    if url[-1] == '/':
        url = url[:len(url)-1]
    for hdirs in most_known_hidden_dirs:
        request_url = requests.get(url+hdirs, verify=False)
        if request_url.status_code == 200:
            print(colored(url, "green")+colored(hdirs,"red"))

def test_urls():
    for i in get_urls():
        request_each_url = requests.get(i, verify=False)
        if request_each_url.status_code <= 299:
            print(f"{colored(i, 'green')} [{colored(request_each_url.status_code, 'green')}]")
        elif request_each_url.status_code >= 300 and request_each_url.status_code <= 399:
            print(f"{colored(i, 'blue')} [{colored(request_each_url.status_code, 'blue')}]")
        elif request_each_url.status_code >= 400 and request_each_url.status_code <= 499:
            print(f"{colored(i, 'yellow')} [{colored(request_each_url.status_code, 'yellow')}]")
        else:
            print(f"{colored(i, 'red')} [{colored(request_each_url.status_code, 'red')}]")
def check_files_for_some_info_disclosure():
    keywords = ['API keys', ' secret', ' password', ' token', ' auth', ' credential', ' key', ' private','Draft', ' secretKey','version','administrator', ' accessKey', ' sessionId', ' cookie', ' jwt', ' config', ' debug', ' env', ' environment', ' connectionString', ' dbPassword', ' user', ' admin', ' root', ' passwd', ' ssh', ' rsa', ' pem', ' privateKey', ' secretToken', ' clientSecret', ' authorization', ' bearer', ' csrf', ' oauth', ' firebase', ' aws_access_key', ' aws_secret_key', ' slack_token', ' google_api_key', ' stripe_key', ' paypal_secret', ' smtp_password', ' encryptionKey', ' decrypt', ' base64', ' hardcoded', ' backup', ' dump', ' log', ' trace', ' error', ' stacktrace', ' debugInfo', ' internal', ' localhost', ' 127.0.0.1', ' dev', ' test', ' staging', ' beta', ' sandbox']
    file_extensions = ['.txt', '.js', '.sql', '.db', '.php', '.html', '.css', '.dtd']
    for extension in file_extensions:
        for url in get_urls():
            if extension in url:
                file_request = requests.get(url, verify=False)
                file_content = file_request.content
                for keyword in keywords:
                    if keyword in file_content.decode('utf-8', errors='ignore'):
                        print(colored(keyword, "red")+colored(f"  founded in: {url}", 'yellow'))

def get_comments():
    comments = re.findall(comments_format, sourcecode, re.DOTALL)
    for comment in comments:
        print(colored(comment, "green"))
    if not comments:
        print(colored("There is no comment!!", "blue"))

print(colored("This part is for Header informations: ", "yellow","on_red"))
infos_from_response_header()

print(colored("This part is for HTTP methods ", "yellow","on_red"))
http_methods_supported_by_The_website()

try:
    print(colored("This part is for urls: ", "yellow","on_red"))
    test_urls()

    print(colored("This part is for comments founded in the website: ", "yellow","on_red"))
    get_comments()

    print(colored("This part is for interesting keywords ", "yellow","on_red"))
    check_files_for_some_info_disclosure()

    print(colored("This part is for hidden directories in the website ", "yellow","on_red"))
    check_for_most_known_hidden_directories()

except Exception as e:
    print(colored("\nEncountred Error, Or you clicked ctrl+c!!"), "red")
