#!/usr/bin/env python
###############################################
# Created by Silas Cutler
#      Silas.Cutler@BlackListThisDomain.com
###############################################
import os
import re
import argparse
import requests


class VT_Rule_Handler(object):
    def __init__(self):
        self.username = ""
        self.password = ""
        self.csrf_token_cache = ""

        # Optional Variables for tweaking
        self.optional_notify = "" #Email Address
        self.optional_daily_limit = 100 # (Untested / Likely should be set to: 10/50/100/500/1000/5000/10000) 

        # Fail out if username/password not set
        if self.username == "" and self.password == "":
            return False

        # Create Requests session for handling requests
        self.session = requests.Session()
        self.session.headers.update({'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) VTUser:{username}'.format(username=self.username)})

        # Setup initial session.
        self.setup()

    # Ensure we keep the most recent CSRF token cached
    def updateCSRFToken(self):
        if 'VT_CSRF' in self.session.cookies:
            self.csrf_token_cache = self.session.cookies['VT_CSRF']
            return True
        return False

    # Login by passing credentials
    def doLogin(self):
        creds = {
            'username': self.username,
            'password': self.password,
            'next': '/intelligence/',
            'response_format': 'json'}
        login_req = self.session.post('https://www.virustotal.com/en/account/signin/', data=creds)
        self.updateCSRFToken()

        try:
            if login_req.json()['signed_in'] == False:
                print "Failed Sign-In"
                return False
            return True
        except Exception, eror:
            print "[X] Failed to login: {error}".format(error=error)
            return False
        return False

    def setup(self):
        # Send initial request
        start_req = self.session.get('https://www.virustotal.com/intelligence/')

        # Set corresponding Headers
        self.session.headers.update({'x-csrftoken': 'null'})
        self.session.headers.update({'referer': 'https://www.virustotal.com/en/signin?next=/intelligence/'})

        if not self.doLogin():
            return False

        hunting_page_req = self.session.get('https://www.virustotal.com/intelligence/hunting/')
        self.updateCSRFToken()

        if self.csrf_token_cache == "":
            return False
        return True

## Functions of object
    def listRules(self, retRules=False):
        return_cache = []

        hunting_page_req = self.session.get('https://www.virustotal.com/intelligence/hunting/')
        self.updateCSRFToken()

        matches = re.findall(r'\s+<option value="([0-9]{5,})">\n\s*(.*?)\n', hunting_page_req.content, re.MULTILINE)
        for rule in matches:
            if retRules:
                return_cache.append([rule[1], rule[0]])
            else:
                print "Name: %s (ID: %s)" % (rule[1], rule[0])

        if retRules:
            return return_cache

    def createRule(self, rName=None):
        yRule = ""
        if rName == None:
            return "[X] Must pass Rule file"

        # Read Yara Rule contents
        inYara = open(rName, 'r')
        yRule = inYara.read()
        inYara.close()

        create = {'notify': self.optional_notify,
                  'daily_limit' : self.optional_daily_limit,
                  'id': '',
                  'name':os.path.basename(rName[:rName.rindex('.')]),
                  'enabled':'true',
                  'csrfmiddlewaretoken': self.csrf_token_cache,
                  'rules': yRule}

        createReq = self.session.post('https://www.virustotal.com/intelligence/hunting/save-ruleset/', data=create)
        jcreateReq = createReq.json()
        if jcreateReq['is_owner'] == "true" and 'id' in jcreateReq.keys():
            print "Created {yara_name}".format(yara_name=jcreateReq['name'])
            return True
        else:
            print "Failed to created rule"
            print "Output:"
            print createReq.content
        return False

    def deleteRule(self, rName):
        rules = self.listRules(True)
        self.updateCSRFToken()

        rule_id = None

        for r in rules:
            if rName == r[0]:
                rule_id = r[1]
                break

        if rule_id:
            delete = {
                'id': rule_id,
                'csrfmiddlewaretoken': self.csrf_token_cache}
            deleteReq = self.session.post('https://www.virustotal.com/intelligence/hunting/delete-ruleset/', data=delete)
            return True
        else:
            print "[X] Could not find rule"

        return False

def is_valid_file(parser, arg):
    if os.path.exists(arg) and (arg.endswith('.yara') or arg.endswith('.yar')):
        return arg
    else:
        parser.error("The file {fname} does not exist!".format(fname=arg))
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", help="List names/ids of Yara rules stored on VT", action="store_true")
    parser.add_argument("--create", help="Add a Yara rule to VT (File Name used as RuleName",
                        metavar="FILE", type=lambda x: is_valid_file(parser, x))
    parser.add_argument("--delete", help="Delete a Yara rule from VT (By Name)", type=str)
    args = parser.parse_args()

    if args.list:
        print "Listing Rules"
        rh = VT_Rule_Handler()
        rh.listRules()

    elif args.create:
        print "Creating {arg}".format(arg=args.create)
        rh = VT_Rule_Handler()
        rh.createRule(args.create)

    elif args.delete:
        print "Deleting {arg}".format(arg=args.delete)
        rh = VT_Rule_Handler()
        rh.deleteRule(args.delete)
    else:
        parser.error("Argument problem")
