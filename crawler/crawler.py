import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import urllib
import threading
import sys
from requests.adapters import HTTPAdapter
import time
from urllib.parse import urlparse
from urllib.parse import urlunparse



requests_header={
    'User-Agent': '-',
    'Accept': '*/*',
    'Accept-Encoding': 'identity', 
}

def redirect_decision(url,initial_ip):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname=='' or hostname==None or hostname==initial_ip:
            parsed_url = parsed_url._replace(scheme='http',netloc=initial_ip)
            new_url = urlunparse(parsed_url)
            return new_url,initial_ip
        if not hostname==initial_ip:
            parsed_url = parsed_url._replace(scheme='http',netloc=initial_ip)
            new_url = urlunparse(parsed_url)
            return new_url,hostname
    except:
        return None,None

        

class SourceAddressAdapter(HTTPAdapter):
    def __init__(self, source_address, **kwargs):
        self.source_address = source_address
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['source_address'] = self.source_address
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['source_address'] = self.source_address
        return super().proxy_manager_for(*args, **kwargs)


source_ip = sys.argv[3]
source_port=0
adapter = SourceAddressAdapter((source_ip,source_port))

f = open(sys.argv[2],'w')
lock = threading.Lock()


def worker(url_and_ip):
    url = url_and_ip[0]
    ip = url_and_ip[1]
    t_start = time.time()
    initial_ip = ip
    session = requests.Session()
    session.mount("http://",adapter)
    session.mount("https://",adapter)
    session.headers.clear()
    session.headers.update({'Host':ip})
    session.headers.update(requests_header)
    
    
    all_urls = [url] 
    banner = ''
    max_size_resource = 0
    max_size_resource_uri = url
    
    initial_request = True
    visited = []
    while(len(all_urls)!=0):
        url = all_urls.pop(0)
        if initial_request:
            _banner, new_urls, resource_size, exceptions = find_and_push_script_and_css(url,session,ip,visited,initial_ip,initial_request=True)
            initial_request = False
        else:
            _banner, new_urls, resource_size, exceptions = find_and_push_script_and_css(url,session,ip,visited,initial_ip,initial_request=False)
        if exceptions!='':
            continue
        if banner=='' and _banner!='':
            banner = _banner
        if resource_size > max_size_resource:
            max_size_resource = resource_size
            max_size_resource_uri = url
        all_urls.extend(new_urls)
        t_now = time.time()
        if int(t_now - t_start) > 120:
        # if int(t_now - t_start) > 60:
            break

    lock.acquire()
    try:
        f.write(str(ip)+'^'+str(banner)+'^'+str(max_size_resource_uri)+'^'+str(max_size_resource)+'^'+str(session.headers['Host'])+'\n')
        f.flush()
    except Exception as e:
        pass
    lock.release()

def find_and_push_script_and_css(url,session,ip,visited,initial_ip,initial_request):
    found_urls = set()
    
    new_url = None
    new_host = None
    try:
        data_size=0
        visited.append(url)  
        
        time.sleep(5)
        with session.get(url,timeout=5,allow_redirects=False,stream=True) as res2:
            data_size = len(res2.raw.read(decode_content=False))
        time.sleep(5)

        with session.get(url,timeout=5,allow_redirects=False,stream=False) as res:
            if res.is_redirect or res.status_code in [301, 302, 303, 307, 308]:
                redirect_url = res.headers['Location']
                new_url,new_host = redirect_decision(redirect_url,initial_ip)
            header_size = 0
            for key in res.headers.keys():
                header_size = header_size + len(key) + len(res.headers[key])    
            resource_size = header_size + data_size

            if not new_url==None:
                found_urls.add(new_url)
                if initial_request==True:
                    new_host_header = {'Host':new_host}
                    session.headers.update(new_host_header)    

            try:
                banner = res.headers['Server']
                banner.replace(',',' ')
            except:
                banner = ''

            try:
                soup = bs(res.content,"html.parser")    
            except:
                return banner,[],resource_size,''

            for tag in soup.find_all():
                uri = tag.attrs.get('src') or tag.get('href')
                if uri=='':
                    continue
                uri = urljoin(url,uri)
                parsed = urllib.parse.urlparse(uri)
                parsed = parsed._replace(scheme='http',netloc=ip)
                result = parsed.geturl()
                if not result in visited:
                    found_urls.add(result)
            del soup
            return banner,list(found_urls),resource_size,''

    except Exception as e:
        return None,None,None,"exc"

if __name__ == '__main__':
    read_lock = threading.Lock()
    from concurrent.futures import ThreadPoolExecutor
    input_file = open(sys.argv[1],'r')


    while(True):
        pool = ThreadPoolExecutor(max_workers=200)    
        line_list = []
        finished = False
        while(True):
            line = input_file.readline()
            if line=='':
                finished = True
                break
            line_list.append(line)
            if len(line_list)==200:
                break
        parameter_list = []


        for line in line_list:
            ip = line.strip()
            url = 'http://' + ip + '/'
            parameter_list.append([url,ip])

        pool.map(worker,parameter_list)
        del pool
        if finished==True:
            break
        



