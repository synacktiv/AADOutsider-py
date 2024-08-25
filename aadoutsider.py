#!/usr/bin/python3

import argparse
import logging
import sys
import shutil
import re
import uuid
import requests
import json
import dns.resolver
import xml.etree.ElementTree as ET

DNS_TCP = False
DNS_RESOLVER = None
OUTPUT = "/dev/stdout"
OUTPUT_FORM = "json"
LOG_LEVEL = logging.info
PROGRESS_FULL_SIZE = 0
PROGRESS_STEP = 0
PROGRESS_CUR_STEP = 0
PROGRESS = 0

def output_data(data):
    output_str = ''

    # Compute output string
    if OUTPUT_FORM == 'json':
        output_str = json.dumps(data)

    elif OUTPUT_FORM == 'csv':
        raise NotImplementedError

    elif OUTPUT_FORM == 'pretty':
        header = list(data[0].keys())
        table_size = {}
        for header_column in header:
            max_column_size = len(header_column)
            for t in data:
                cur_column_size = len(str(t[header_column]))
                if cur_column_size > max_column_size:
                    max_column_size = cur_column_size
            table_size[header_column] = max_column_size

        row_format = '\t'.join([f'{{:<{table_size[cur_header]}}}' for cur_header in header])
        output_str += row_format.format(*header) + '\n'
        output_str += row_format.format(*['-' * len(cur_header) for cur_header in header]) + '\n'

        for cur_data in sorted(data, key=lambda item: item['Name'].lower()):
            output_str += row_format.format(*[str(cur_data[cur_header]) for cur_header in header]) + '\n'

    output_str += '\n'

    # Write string to disk
    with open(OUTPUT, 'w') as f:
        if f.isatty():
            # Special case for stdout to separate output from logging info
            output_str = '\n' + output_str
        f.write(output_str)

def init_progress(full_size):
    global PROGRESS_STEP
    global PROGRESS_CUR_STEP
    global PROGRESS

    if LOG_LEVEL == logging.DEBUG or not sys.stderr.isatty():
        return

    bar_size = min(shutil.get_terminal_size(fallback=(20,0))[0], full_size + 2)

    PROGRESS_STEP = full_size // (bar_size - 2)  # Need to account for the brackets
    PROGRESS_CUR_STEP = 0
    PROGRESS = 0

    sys.stderr.write(f'[{" " * (bar_size - 2)}]')
    sys.stderr.flush()
    sys.stderr.write('\b' * (bar_size-1))

def add_progress():
    global PROGRESS_STEP
    global PROGRESS_CUR_STEP
    global PROGRESS

    if LOG_LEVEL == logging.DEBUG or not sys.stderr.isatty():
        return

    if PROGRESS_CUR_STEP >= PROGRESS:
        sys.stderr.write('=')
        sys.stderr.flush()
        PROGRESS += PROGRESS_STEP

    PROGRESS_CUR_STEP += 1
    return

def end_progress():
    if LOG_LEVEL == logging.DEBUG or not sys.stderr.isatty():
        return
    sys.stderr.write('\r\033[K')
    sys.stderr.flush()

def get_dns_resolver():
    resolver = dns.resolver.Resolver()
    if DNS_RESOLVER != None:
        resolver.nameservers = DNS_RESOLVER
    return resolver

def dns_query(domain, mytype, ignore_error=False):

    error = False
    resolver = get_dns_resolver()
    res = []
    try:
        full_resp = resolver.resolve(domain, mytype, tcp=DNS_TCP, raise_on_no_answer=False)
        if mytype == 'MX':
            for resp in full_resp:
                res.append(re.sub(r'\.*$', '', resp.exchange.to_text()))
        elif len(full_resp.response.answer) != 0:
            for resp in [item for t in full_resp.response.answer for item in t]:
                resp = str(resp)
                # Removing any trailing dots
                res.append(re.sub(r'\.*$', '', resp))
    except dns.resolver.NXDOMAIN:
        # Domain explicitely not existing
        if ignore_error:
            res = []
        else:
            raise
    except Exception as e:
        logging.warning(f'Got the following exception while querying {domain} for {mytype} type: {type(e)} - {e}')
        raise

    return res

def does_exist(domain):
    # This function is a bit weird, in the sense that a domain could have no DNS record registered to
    # its name, yet it could "exist", ie. the Reply code in the DNS response is 0, aka. "No error".
    # This behavior is reproduced in this function to match the behavior of the Resolve-DnsName
    # powershell cmdlet and how it is used in AADInternals.

    res = []
    error = False

    try:
        res += dns_query(domain, 'A')
    except Exception:
        error = True
    try:
        res += dns_query(domain, 'AAAA')
    except Exception:
        error = True

    return not (error and len(res) == 0)

def get_tenant_id(domain=None, username=None, accesstoken=None):
    if accesstoken is not None:
        raise NotImplementedError("Tenant ID from access token retrieval is not yet implemented")

    if domain is None:
        domain = username.split('@')[-1]

    try:
        resp = requests.get(f'https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain={domain}').text
        formated_resp = json.loads(resp)

        if 'tenantId' not in formated_resp:
            return None

        return formated_resp['tenantId']

    except Exception:
        raise RuntimeError('Cannot query/parse remote service')

def get_credential_type(username=None, flowtoken=None, originalrequest=None, subscope=None):
    body = {
        "username": username,
        "isOtherIdpSupported": True,
        "checkPhones": True,
        "isRemoteNGCSupported": False,
        "isCookieBannerShown": False,
        "isFidoSupported": False,
        "originalRequest": originalrequest,
        "flowToken": flowtoken
    }

    if originalrequest is not None:
        body['isAccessPassSupported'] = True

    return json.loads(requests.post(f'{get_tenant_login_url(subscope)}/common/GetCredentialType', headers={'ContentType': 'application/json; charset=UTF-8'}, data=json.dumps(body)).text)

def has_cba(username, subscope=None):
    try:
        return get_credential_type(username=username, subscope=subscope)['Credentials']['HasCertAuth'] == True
    except KeyError:
        return False

def has_desktop_sso(domain, subscope=None):
    try:
        return get_credential_type(f'nn@{domain}', subscope=subscope)['EstsProperties']['DesktopSsoEnabled'] == True
    except KeyError:
        return False

def has_cloud_mx(domain, subscope):
    if subscope == 'DOD':
        myfilter = '.protection.office365.us'
    elif subscope == 'DODCON':
        myfilter = '.protection.office365.us'
    else:
        myfilter = '.mail.protection.outlook.com'

    return any([t.endswith(myfilter) for t in dns_query(domain, 'MX', ignore_error=True)])

def has_cloud_spf(domain, subscope):
    if subscope == 'DOD':
        myfilter = 'include:spf.protection.office365.us'
    elif subscope == 'DODCON':
        myfilter = 'include:spf.protection.office365.us'
    else:
        myfilter = 'include:spf.protection.outlook.com'

    return any([myfilter in t for t in dns_query(domain, 'TXT', ignore_error=True)])

def has_cloud_dmarc(domain):
    # DMARC TXT record are double quoted, hence the "
    return any([t.startswith('"v=DMARC1') for t in dns_query(f'_dmarc.{domain}', 'TXT', ignore_error=True)])

def has_cloud_dkim(domain, subscope=None):
    if subscope == 'DOD':
        myfilter = r'.*_domainkey\..*\.onmicrosoft\.us.*'
    elif subscope == 'DODCON':
        myfilter = r'.*_domainkey\..*\.onmicrosoft\.us.*'
    else:
        myfilter = r'.*_domainkey\..*\.onmicrosoft\.com.*'

    domains = [f'selector1._domainkey.{domain}', f'selector2._domainkey.{domain}']
    for check_domain in domains:
        for resp in dns_query(check_domain, 'CNAME', ignore_error=True):
            if re.match(myfilter, resp) is not None:
                return True
    return False

def has_cloud_mtasts(domain, subscope=None):
    if subscope == 'DOD':
        myfilter = r'.*_domainkey\..*\.onmicrosoft\.com.*'
    elif subscope == 'DODCON':
        myfilter = r'.*mx: .*\.mail\.protection\.office365\.us.*'
    else:
        myfilter = r'.*mx: .*\.mail\.protection\.outlook\.com.*'

    url = f'https://mta-sts.{domain}/.well-known/mta-sts.txt'
    mta_sts_found = False
    outlook_mx_found = False

    try:
        for line in requests.get(url, timeout=5).text.splitlines():
            if line == "version: STSv1":
                mta_sts_found = True
            if re.match(r'.*mx: .*\.mail\.protection\.outlook\.com.*', line) is not None:
                outlook_mx_found = True
    except Exception:
        mta_sts_found = False
        outlook_mx_found = False

    return mta_sts_found and outlook_mx_found
        

def get_openid_configuration(domain=None, username=None):
    if domain is None:
        domain = username.split('@')[-1]

    resp = requests.get(f'https://login.microsoftonline.com/{domain}/.well-known/openid-configuration').text
    return json.loads(resp)

def get_tenant_subscope(domain=None, openid_config=None):
    if not openid_config:
        openid_config = get_openid_configuration(domain)

    try:
        return openid_config['tenant_region_sub_scope']
    except Exception:
        return None

def get_tenant_login_url(subscope=None):
    if subscope == "DOD":
        return 'https://login.microsoftonline.us'
    elif subscope == "DODCON":
        return 'https://login.microsoftonline.us'
    else:
        return 'https://login.microsoftonline.com'

def get_user_realm_v2(username, subscope=None):
    return json.loads(requests.get(f'{get_tenant_login_url(subscope)}/GetUserRealm.srf?login={username}').text)

def get_mdi_instance(tenant):
    tenant = tenant.split('.')[0]

    logging.debug(f'Getting MDI instance for {tenant}')

    domains = [f'{tenant}.atp.azure.com', f'{tenant}-onmicrosoft-com.atp.azure.com']
    for domain in domains:
        if does_exist(domain):
            return domain

    return None

def get_tenant_domains(domain, subscope=None):
    if not subscope:
        subscope = get_tenant_subscope(domain=domain)

    if subscope == 'DOD':
        uri = 'https://autodiscover-s-dod.office365.us/autodiscover/autodiscover.svc'
    elif subscope == 'DODCON':
        uri = 'https://autodiscover-s.office365.us/autodiscover/autodiscover.svc'
    else:
        uri = 'https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc'

    domains = []
    body = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<soap:Header>
		<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
		<a:To soap:mustUnderstand="1">{uri}</a:To>
		<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		</a:ReplyTo>
	</soap:Header>
	<soap:Body>
		<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
			<Request>
				<Domain>{domain}</Domain>
			</Request>
		</GetFederationInformationRequestMessage>
	</soap:Body>
</soap:Envelope>"""
    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
        'User-Agent': 'AutodiscoverClient'
    }
    namespaces = {'s': 'http://schemas.xmlsoap.org/soap/envelope/', 'a': 'http://www.w3.org/2005/08/addressing'}
    xpath_query = './s:Body/{http://schemas.microsoft.com/exchange/2010/Autodiscover}GetFederationInformationResponseMessage/{http://schemas.microsoft.com/exchange/2010/Autodiscover}Response/{http://schemas.microsoft.com/exchange/2010/Autodiscover}Domains/{http://schemas.microsoft.com/exchange/2010/Autodiscover}Domain'

    resp = requests.post(uri, headers=headers, data=body).text
    root = ET.fromstring(resp)
    for domain_elt in root.findall(xpath_query, namespaces=namespaces):
        domains.append(domain_elt.text)

    if domain not in domains:
        domains.append(domain)

    return sorted(domains)

def does_user_exist(user, method="normal", subscope=None):
    method = method.lower()
    allowed_methods = ['normal', 'login', 'autologon', 'rst2']
    if method not in allowed_methods:
        raise RuntimeError(f'Parameter "method" for function "does_user_exist" invalid, should be one of {allowed_methods} but got "{method}"')

    # Will stay None if the method was not able to confirm or not
    # that the account exists
    exists = None

    if not subscope:
        subscope = get_tenant_subscope(user.split('@')[-1])

    if method == "normal":
        cred_type = get_credential_type(user, subscope=subscope)
        if cred_type['ThrottleStatus'] == 1:
            logging.warning('Request throttled!')
        else:
            exists = cred_type['IfExistsResult'] == 0 or cred_type['IfExistsResult'] == 6

    elif method == 'login':
        random_guid = uuid.uuid4()
        body = {
            'resource': str(random_guid),
            'client_id': str(random_guid),
            'grant_type': 'password',
            'username': user,
            'password': 'none',
            'scope': 'openid'
        }
        response = requests.post(f'{get_tenant_login_url(subscope)}/common/oauth2/token', headers={'ContentType': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1'}, data=body)
        parsed_resp = json.loads(response.text)
        if 'The user account {EUII Hidden} does not exist in the' in parsed_resp['error_description']:
            exists = False
        elif 'Error validating credentials due to invalid username or password.' in parsed_resp['error_description']:
            exists = True

    elif method == 'autologon' or method == 'rst2':
        raise NotImplementedError('Method Autologon and RST2 are not yet implemented')

    return exists

def recon_as_outsider(domain_name=None, username=None, single=False, get_relaying_parties=False):
    if domain_name is None and username is None:
        logging.warning('No domain nor username was provided')
        return

    if domain_name is None:
        domain_name = username.split('@')[-1]
        tenant_cba = has_cba(username)

    tenant_id = get_tenant_id(domain_name)
    if tenant_id is None:
        logging.warning(f'Domain {domain_name} is not registered to Azure')
        return

    openid_config = get_openid_configuration(domain=domain_name)

    tenant_name = None
    tenant_brand = None
    tenant_region = openid_config['tenant_region_scope']
    tenant_subscope = get_tenant_subscope(openid_config=openid_config)
    tenant_sso = None
    tenant_cba = None

    domains_info = []
    domains = get_tenant_domains(domain_name, subscope=tenant_subscope)
    logging.info(f'Found {len(domains)} domains!')

    init_progress(len(domains))

    for domain in domains:
        exists = False
        has_cloud_MX = False
        has_cloud_SPF = False
        has_cloud_DMARC = False
        has_cloud_DKIM = False
        has_cloud_MTASTS = False
        auth_url = ""

        add_progress()

        if tenant_name is None and re.match(r'^[^.]*\.onmicrosoft\.(com|us)$', domain.lower()) is not None:
            tenant_name = domain

        if tenant_sso is None:
            tenant_sso = has_desktop_sso(domain=domain, subscope=tenant_subscope)

        resolver = get_dns_resolver()
        if not single or (single and domain_name.lower() == domain.lower()):
            exists = does_exist(domain)
            if exists:
                has_cloud_MX = has_cloud_mx(domain, subscope=tenant_subscope)
                has_cloud_SPF = has_cloud_spf(domain, subscope=tenant_subscope)
                has_cloud_DMARC = has_cloud_dmarc(domain)
                has_cloud_DKIM = has_cloud_dkim(domain, subscope=tenant_subscope)
                has_cloud_MTASTS = has_cloud_mtasts(domain, subscope=tenant_subscope)

            realm_info = get_user_realm_v2(f'nn@{domain}', subscope=tenant_subscope)
            if tenant_brand is None:
                try:
                    tenant_brand = realm_info['FederationBrandName']
                except KeyError:
                    pass

            relaying_parties = []

            try:
                auth_url = realm_info['AuthURL']
            except KeyError:
                pass
            else:
                if get_relaying_parties:
                    idp_url = auth_url.rpartition('/')[0] + '/idpinitiatedsignon.aspx'
                    try:
                        page = requests.get(idp_url)
                    except Exception:
                        logging.warning(f'Cannot query idp_url: {idp_url}')
                    logging.debug(f'Getting relaying parties for {domain} from {idp_url}')
                    try:
                        page_root = ET.fromstring(page.text)
                        res = page_root.findall(".//select[@id='idp_RelyingPartyDropDownList']/option")
                        logging.debug(f'Got {len(res)} relaying parties from {idp_url}')
                    except Exception:
                        pass
                    else:
                        for cur_option in res:
                            relaying_parties.append(cur_option.text)

                auth_url = auth_url.split('/')[2]

            attributes = {
                'Name': domain,
                'DNS': exists,
                'MX': has_cloud_MX,
                'SPF': has_cloud_SPF,
                'DMARC': has_cloud_DMARC,
                'DKIM': has_cloud_DKIM,
                'MTA-STS': has_cloud_MTASTS,
                'Type': realm_info['NameSpaceType'],
                'STS': auth_url
            }

            if get_relaying_parties:
                attributes['RPS'] = relaying_parties

            domains_info.append(attributes)

    end_progress()

    logging.info(f'Tenant brand: {tenant_brand}')
    logging.info(f'Tenant name: {tenant_name}')
    logging.info(f'Tenant id: {tenant_id}')
    logging.info(f'Tenant region: {tenant_region}')

    if tenant_subscope:
        logging.info(f'Tenant sub region: {tenant_subscope}')

    if not single or tenant_sso:
        logging.info(f'DesktopSSO enabled: {tenant_sso}')

    if tenant_name is not None:
        tenant_mdi = get_mdi_instance(tenant_name)
        if tenant_mdi is not None:
            logging.info(f'MDI instance: {tenant_mdi}')

    if does_user_exist(f'ADToAADSyncServiceAccount@{tenant_name}'):
        logging.info(f'Uses cloud sync: True')

    if tenant_cba is not None:
        logging.info(f'CBA enabled: {tenant_cba}')

    output_data(domains_info)

def user_enumeration_as_outsider(username, method='normal', external=False, domain=None):
    tenant_subscope = get_tenant_subscope(username.split('@')[-1])

    if method == 'normal' and external:
        if not domain:
            logging.error('Required domain parameter not given')
            exit(1)
        # User is external, we need to change its email address
        username = f'{username.replace("@", "_")}#EXT#@{domain}'

    exists = does_user_exist(username, method=method, subscope=tenant_subscope)
    if exists:
        logging.info(f'User {username} exists')
    elif exists is None:
        logging.info(f'Could not determine if {username} exists')
    else:
        logging.info(f'User {username} does not exist')

def main():
    global DNS_TCP
    global DNS_RESOLVER
    global OUTPUT
    global OUTPUT_FORM
    global LOG_LEVEL

    parser = argparse.ArgumentParser(description='AADInternals-Recon.py - The Python equivalent of AADInternals recon as outsider')
    parser.add_argument('--dns-tcp', action='store_true', help='Use TCP instead of UDP for DNS requests', default=False)
    parser.add_argument('--dns', action='append', help='Use this specific DNS (can be used multiple times)', default=[])
    parser.add_argument('-v', '--verbose', action='store_true', default=False)

    # subparsers
    subparsers = parser.add_subparsers(help='cmdlet to call', dest='cmdlet')

    # cmdlet ReconAsOutsider
    parser_a = subparsers.add_parser('recon', help='ReconAsOutsider')
    parser_a.add_argument('-d', '--domain', type=str, help='targeted domain')
    parser_a.add_argument('-u', '--username', type=str, help='targeted username')
    parser_a.add_argument('-s', '--single', action='store_true', help='only perform advanced checks for the targeted domain', default=False)
    parser_a.add_argument('-r', '--relayingparties', action='store_true', help='retrieve relaying parties of STSs', default=False)
    parser_a.add_argument('-o', '--output', help='output file', default='/dev/stdout')
    parser_a.add_argument('-of', '--output-form', help='output format', default='pretty', choices=['json','csv','pretty'])
    
    # cmdlet UserEnumerationAsOutsider
    parser_enum = subparsers.add_parser('user_enum', help='UserEnumerationAsOutsider')
    parser_enum.add_argument('username', help='user to test')
    parser_enum.add_argument('-m', '--method', choices=['normal','login','autologon','rst2'], help='enumeration method', default='normal')
    parser_enum.add_argument('-e', '--external', action='store_true')
    parser_enum.add_argument('-d', '--domain', type=str, default=None)
    args = parser.parse_args()

    # Simple logging configuration
    LOG_LEVEL = logging.INFO
    if args.verbose:
        LOG_LEVEL = logging.DEBUG
    logging.basicConfig(format='%(levelname)s: %(message)s', level=LOG_LEVEL)

    # DNS configuration
    DNS_TCP = args.dns_tcp
    if len(args.dns) > 0:
        DNS_RESOLVER = args.dns

    if args.cmdlet == 'recon':
        OUTPUT = args.output
        OUTPUT_FORM = args.output_form
        recon_as_outsider(domain_name=args.domain, username=args.username, single=args.single, get_relaying_parties=args.relayingparties)
    elif args.cmdlet == 'user_enum':
        user_enumeration_as_outsider(username=args.username, method=args.method, external=args.external, domain=args.domain)
    else:
        parser.print_help()
        exit(1)

if __name__ == "__main__":
    main()

