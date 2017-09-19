#!/usr/bin/env python2
import ipaddress

def get_google_subnet(ipv6=False):
    """
    According to: Static IP Addresses and App Engine apps in https://cloud.google.com/appengine/kb/
    yields the list of google subnets as queried from the main record
    ipv6: if True returns ipv6 blocks too
    """
    import dns.resolver
    res = dns.resolver.query('_cloud-netblocks.googleusercontent.com.', 'TXT')
    for rdata in res:
        for txt_string in rdata.strings:
            splitdata = txt_string.split(" ")
            for line in splitdata:
                if "include" in line:
                    res_next = dns.resolver.query(line.split(':')[1] + '.', 'TXT')
                    for rdata_next in res_next:
                        for txt_string_next in rdata_next.strings:
                            splidata_next = txt_string_next.split(" ")
                            for line_next in splidata_next:
                                if "ip6:" in line_next and ipv6: yield line_next.split(':', 1)[1]
                                if "ip4:" in line_next: yield line_next.split(':', 1)[1]

def get_aws_subnet(json_file_path="ip-ranges.json", ipv6=False):
    """
    According to http://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html#aws-ip-download
    Copy file from https://ip-ranges.amazonaws.com/ip-ranges.json
    
    Notes: currently does not check region or service
    ipv6: *** Unimplemented. to implement see ipv6_prefixes in json ***
    """
    import json
    with open(json_file_path, "r") as f:
        l = json.load(f)
        for ip_block in l["prefixes"]:
            yield ip_block["ip_prefix"]

def get_azure_subnet(xml_file_path="PublicIPs_20170918.xml"):
        """
        According to https://www.microsoft.com/en-us/download/details.aspx?id=41653
        Copy file (as for time of writing) from https://download.microsoft.com/download/0/1/8/018E208D-54F8-44CD-AA26-CD7BC9524A8C/PublicIPs_20170918.xml
        """
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        for region in root:
            for ip_range in region:
                yield ip_range.attrib["Subnet"]

def in_subnet(ip, subnet):
    """
    checks if an ip is in given subnet
    Note: currently returning False without notice if bad ip
    """
    try:
        return ipaddress.ip_address(unicode(ip)) in ipaddress.ip_network(unicode(subnet))
    except ValueError:
        return False

def check_known(ip_list, resultfile, use_progressbar=False, ignore_none=False):
    google_subnet = list(get_google_subnet())
    aws_subnet = list(get_aws_subnet())
    azure_subnet = list(get_aws_subnet())

    if use_progressbar:
        from tqdm import tqdm

    for ip in tqdm(ip_list):
        src = None
        for subnet in google_subnet:
            if in_subnet(ip, subnet):
                src = "Google"
                continue
        if not src:
            for subnet in aws_subnet:
                if in_subnet(ip, subnet):
                    src = "AWS"
                    continue
        if not src:
            for subnet in azure_subnet:
                if in_subnet(ip, subnet):
                    src = "Azure"
                    continue
        if not ignore_none or src != None:
            resultfile.write("%s: %s\n" % (ip, src))

if "__main__" == __name__:
    #ip_list_fpath = "../dhs-ips-newlines-clear.txt"
    
    # Get list of ips to check from file, set to remove dups
    #ip_list = set(line.strip() for line in open(ip_list_fpath, "r"))
    # The list has problematic entries too.
    #ip_list.remove('')
    
    # cvs list
    import csv
    with open('i.csv', 'r') as csvf:
        reader = csv.reader(csvf)
        ip_list = set(row[0] for row in reader)
        
        with open('csvresult.res', 'w') as res:
            check_known(ip_list, res, True, False)
