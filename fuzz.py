import subprocess, traceback, argparse, requests, os, time, json, sys
from bs4 import BeautifulSoup, SoupStrainer

cfg_file = "cfg.json"
help_file = "help_message.txt"

class MyArgumentParser(argparse.ArgumentParser):
    #Custom help message
    def print_help(self):
        with open(help_file, 'r+') as f:
            self.help_message = f.read()
            f.close()
        print(self.help_message)
        exit(-1)

class Fuzzer:
    def __init__(self):
        self.parser = MyArgumentParser(description='Parse command line arguments', usage='python fuzz.py COMMANDS url OPTIONS')
        with open(cfg_file, 'r+') as f:
            self.cfg = json.loads(f.read())
            f.close()

    def start_xampp(self):
        start = os.path.join(self.cfg["xampp_path"], "xampp_start.exe")
        subprocess.run(start)

    def stop_xampp(self):
        stop = os.path.join(self.cfg["xampp_path"], "xampp_stop.exe")
        subprocess.run(stop)

    def parse_args(self):
        self.session = requests.session()
        self.parser.add_argument('COMMANDS')
        self.parser.add_argument('url')
        self.parser.add_argument('--custom-auth', default=None)
        self.parser.add_argument('--common-words', default=None)
        self.parser.add_argument('--extensions', default=".php")
        self.parser.add_argument('--vectors', default=None)
        self.parser.add_argument('--sanitized-chars', default=None)
        self.parser.add_argument('--sensitive', default=None)
        self.parser.add_argument('--slow', default="500")
        self.args = self.parser.parse_args()

        self.timeout = float(self.args.slow)/1000

        if self.args.COMMANDS == "discover":
            self.discover()
        elif self.args.COMMANDS == "test":
            if self.args.sanitized_chars:
                char_file = self.args.sanitized_chars
                text = self.check_for_file(char_file)
                if text:
                    self.sanitized_chars = text.split("\n")
                else:
                    self.sanitized_chars = ["<",">"]
            else:
                self.sanitized_chars = ["<",">"]
            
            if not self.args.vectors:
                print("fuzz.py: error: the following arguments are required: --vectors")
                sys.exit()
            else:
                vector_file = self.args.vectors
                text = self.check_for_file(vector_file)
                if text:
                    self.vectors = text.split("\n")
                else:
                    print("fuzz.py: error: vector file has no contents")
                    sys.exit()

            if not self.args.sensitive:
                print("fuzz.py: error: the following arguments are required: --sensitive")
                sys.exit()
            else:
                sensitive_file = self.args.sensitive
                text = self.check_for_file(sensitive_file)
                if text:
                    self.sensitive_info = text.split("\n")
                else:
                    print("fuzz.py: error: sensitive information file has no contents")
                    sys.exit()
            
            self.discover()
            print("Testing with vectors...\nThis may take a while with a large vectors file...")
            self.test()

    def check_for_file(self, file):
        text = None
        try:
            with open(file, 'r+') as f:
                text = f.read()
                f.close()
            return text
        except:
            print("fuzz.py: error: unable to open file {}".format(file))
            sys.exit()

    def print_page(self, url):
        response = self.session.get(url)
        print(response.text)

    def link_status(self, url):
        try:
            self.response = self.session.get(url, timeout=self.timeout)
            return self.response.status_code
        except:
            print("fuzz.py: warning: timeout exceeded for {}".format(url))
            return 404

    def discover(self):
        self.path = self.args.url
        if self.args.custom_auth:
            if self.args.custom_auth == "dvwa":
                self.path = self.path + "/" + self.args.custom_auth
                self.auth_dvwa()
            else:
                self.print_page(self.path)
        if not self.args.common_words:
            print("fuzz.py: error: the following arguments are required: --common-words")
            sys.exit()
        else:
            with open(self.args.common_words, 'r+') as f:
                self.words = f.read().split("\n")
                f.close()
            self.guess_pages()
            self.found_html = []
            self.discovered_links = []
            self.input_params = {}
            self.get_links(self.path)
            for page in self.guessed_links:
                self.get_links(page)
            self.discover_report()

    def guess_pages(self):
        self.guessed_links = []
        for word in self.words:
            if "." not in word:
                word = word + self.args.extensions
            page = self.path + "/" + word
            if self.link_status(page) == 200:
                self.guessed_links.append(page)
        return self.guessed_links

    def get_links(self, url):
        self.discovered_links.append(url)
        if self.link_status(url) == 200:
            if self.response.text not in self.found_html:
                self.found_html.append(self.response.text)
                self.get_inputs(url)

                soup = BeautifulSoup(self.response.text, features="lxml")
                for link in soup.find_all('a'):
                    new_path = link.get('href')
                    if new_path != None and "http" not in str(new_path):
                        new_path = self.path + "/" + new_path.replace("./","").replace("..","")
                        if new_path not in self.discovered_links and self.args.url in new_path:
                            self.get_links(new_path)

                    new_path = link.get('rel')
                    if new_path != None and "http" not in str(new_path):
                        new_path = self.path + "/" + new_path.replace("./","").replace("..","")
                        if new_path not in self.discovered_links and self.args.url in new_path:
                            self.get_links(new_path)

    def get_inputs(self, path):
        html = self.session.get(path)
        soup = BeautifulSoup(html.text, 'lxml')
        self.input_params[path] = []
        for form in soup.find_all(["input"]):
            if 'name' in form.attrs:
                self.input_params[path].append(form)

    def discover_report(self):
        print("LINKS FOUND ON PAGE:\n====================")
        for link in self.discovered_links:
            print(link)
        print("====================")
        print("LINKS SUCCESSFULLY GUESSED:\n====================")
        for link in self.guessed_links:
            print(link)
        print("====================")
        print("INPUT FORMS ON PAGES:\n====================")
        for page in self.input_params:
            if self.input_params[page] != []:
                print(page)
                print("**********\n*Name*Value*\n**********\n    **********")
                for form in self.input_params[page]:
                    if 'name' in form.attrs and 'value' in form.attrs:
                        print("    *{}*{}*".format(form.attrs['name'], form.attrs['value']))
                    elif 'value' not in form.attrs:
                        print("    *{}*    *".format(form.attrs['name']))
                print("    **********")
        print("====================")
        print("COOKIES")
        for cookie in self.session.cookies:
            print(cookie)
        print("====================")

    def test(self):
        self.num_unsanitized = 0
        self.num_sql_inject_vb = 0
        self.num_sensitive_leaks = 0
        self.num_dos_vb = 0
        self.num_response_errors = 0
        self.test_vectors()
        self.test_report()

    def test_vectors(self):
        for page in self.input_params:
            if self.input_params[page] != []:
                for vector in self.vectors:
                    response = self.session.get(page)
                    payload = {"form" : "submit"}
                    for form in self.input_params[page]:
                        if form.attrs['type'] == "text" or form.attrs['type'] == "password":
                            payload[form.attrs['name']] = vector
                        elif 'value' in form.attrs:
                            payload[form.attrs['name']] = form.attrs['value']
                        self.num_sql_inject_vb += 1
                    post = self.session.post(page, data=payload)
                    self.test_sanitized(post)
                    self.test_sensitive(post)
                    self.test_response(post)
        for page in self.discovered_links:
            response = self.session.get(page)
            self.test_sanitized(response)
            self.test_sensitive(response)
            self.test_response(response)

    def test_sanitized(self, response):
        soup = BeautifulSoup(response.content, 'html.parser')
        for char in self.sanitized_chars:
            for item in soup.find_all("pre"):
                line = str(item.text).strip()
                if char in line and line != "":
                    print(str(item))
                    self.num_unsanitized += 1

    def test_sensitive(self, response):
        for info in self.sensitive_info:
            for line in response.text.split("\n"):
                line = str(line).replace('<pre>','').replace('</pre>','').strip()
                if info in line and line != "":
                    print(line)
                    self.num_sensitive_leaks += 1

    def test_response(self, response):
        if response.status_code != 200:
            self.num_response_errors += 1
            print("-----------------ERROR-----------------")
            print(str(response.status_code) + " => {} for {}".format(response.reason, response.url))

    def test_report(self):
        print("*************************************")
        print("*          TEST RESULTS:            *")
        print("*************************************")
        print("Number of Unsanitized inputs: {}".format(str(self.num_unsanitized)))
        print("Number of Possible SQL Injection Vulnerabilities: {}".format(str(self.num_sql_inject_vb)))
        print("Number of possible Sensitive Data Leakages: {}".format(str(self.num_sensitive_leaks)))
        print("Number of possible DOS vulnerabilities: {}".format(str(self.num_dos_vb)))
        print("Number of HTTP/Response Code Errors: {}".format(str(self.num_response_errors)))

    def auth_dvwa(self):
        self.setup_file = self.path + "/setup.php"
        self.login_file = self.path + "/login.php"
        self.security_file = self.path + "/security.php"

        response = self.session.get(self.setup_file)
        soup = BeautifulSoup(response.content, 'html.parser')
        payload = {"create_db" : "Create / Reset Database", "form" : "submit"}
        token = soup.find(lambda tag: tag.get('name') == 'user_token')
        if token:
            payload["user_token"] = token.get('value')
        post = self.session.post(self.setup_file, data=payload)

        payload = {"username" : "admin", "password" : "password", "Login" : "Login", "form" :"submit"}
        response = self.session.get(self.login_file)
        soup = BeautifulSoup(response.content, 'html.parser')
        token = soup.find(lambda tag: tag.get('name') == 'user_token')
        if token:
            payload["user_token"] = token.get('value')
        post = self.session.post(self.login_file, data=payload)

        payload = {"seclev_submit" : "Submit", "security":"low", "form":"submit"}
        response = self.session.get(self.security_file)
        soup = BeautifulSoup(response.content, 'html.parser')
        token = soup.find(lambda tag: tag.get('name') == 'user_token')
        if token:
            payload["user_token"] = token.get('value')
        self.session.cookies["security"] = "low"
        post = self.session.post(self.security_file, data=payload)
        response = self.session.get(self.path)
        print(response.text)
        
if __name__ == "__main__":
    f = Fuzzer()
    f.parse_args()