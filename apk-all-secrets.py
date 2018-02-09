#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import sys
import math
import datetime
import argparse
import tempfile
import os
import re
import json
import stat
try:
    from defaultRegexes.regexChecks import regexes
except ImportError:
    from regexChecks import regexes

def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of an android apk file.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument("--rules", dest="rules", help="Ignore default regexes and source from json list file")
    parser.add_argument('package_path', type=str, help='path to folder containing apktool extracted package for secret searching, e.g. /home/ubuntu/com.facebook.katana')
    parser.set_defaults(rules={})
    args = parser.parse_args()

    rules = {}
    if args.rules:
        try:
            with open(args.rules, "r") as ruleFile:
                rules = json.loads(ruleFile.read())
                for rule in rules:
                    rules[rule] = re.compile(rules[rule])
        except (IOError, ValueError) as e:
            raise("Error reading rules file")
        for regex in dict(regexes):
            del regexes[regex]
        for regex in rules:
            regexes[regex] = rules[regex]

    output = find_strings(args.package_path, args.output_json)

def str2bool(v):
    if v == None:
        return True
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)

def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_results(printJson, issue):
    printableDiff = issue['printDiff']
    reason = issue['reason']
    path = issue['path']

    if printJson:
        print(json.dumps(issue, sort_keys=True, indent=4))
    else:
        print("~~~~~~~~~~~~~~~~~~~~~")
        reason = "{}Reason: {}{}".format(bcolors.OKGREEN, reason, bcolors.ENDC)
        print(reason)
        dateStr = "{}Date: {}{}".format(bcolors.OKGREEN, commit_time, bcolors.ENDC)
        print(dateStr)
        hashStr = "{}Hash: {}{}".format(bcolors.OKGREEN, commitHash, bcolors.ENDC)
        print(hashStr)
        filePath = "{}Filepath: {}{}".format(bcolors.OKGREEN, path, bcolors.ENDC)
        print(filePath)

        if sys.version_info >= (3, 0):
            branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name, bcolors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit, bcolors.ENDC)
            print(commitStr)
            print(printableDiff)
        else:
            branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name.encode('utf-8'), bcolors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit.encode('utf-8'), bcolors.ENDC)
            print(commitStr)
            print(printableDiff.encode('utf-8'))
        print("~~~~~~~~~~~~~~~~~~~~~")

def find_entropy(file):
    stringsFound = []
    f = open(file, "r")
    for line in f:
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5:
                    print file+" "+string
                    stringsFound.append(string)
                    line = line.replace(string, bcolors.WARNING + string + bcolors.ENDC)
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    stringsFound.append(string)
                    line = line.replace(string, bcolors.WARNING + string + bcolors.ENDC)
    entropicDiff = None
    if len(stringsFound) > 0:
        entropicDiff = {}
        entropicDiff['stringsFound'] = stringsFound
        entropicDiff['printDiff'] = file
        entropicDiff['reason'] = "High Entropy"
    return entropicDiff

def regex_check(file, custom_regexes={}):
    if custom_regexes:
        secret_regexes = custom_regexes
    else:
        secret_regexes = regexes
    regex_matches = []
    for key in secret_regexes:
        found_strings = secret_regexes[key].findall(printableDiff)
        for found_string in found_strings:
            found_diff = printableDiff.replace(printableDiff, bcolors.WARNING + found_string + bcolors.ENDC)
        if found_strings:
            foundRegex = {}
            foundRegex['date'] = commit_time
            foundRegex['path'] = blob.b_path if blob.b_path else blob.a_path
            foundRegex['branch'] = branch_name
            foundRegex['commit'] = prev_commit.message
            foundRegex['diff'] = blob.diff.decode('utf-8', errors='replace')
            foundRegex['stringsFound'] = found_strings
            foundRegex['printDiff'] = found_diff
            foundRegex['reason'] = key
            foundRegex['commitHash'] = commitHash
            regex_matches.append(foundRegex)
    return regex_matches




def find_strings(package_path, printJson=False, custom_regexes={}):
    output = {"foundIssues": []}

    #for root, dirs, files in os.walk(package_path):
        #print root
    #    print dirs
        #print files
    #    for file in files:
    #    	print file
    
    for path, directories, files in os.walk(package_path):
        for file in files:
            #print 'found %s' % os.path.join(path, file)
            foundIssues = []
            entropicDiff = find_entropy(os.path.join(path, file))
            if entropicDiff:
                foundIssues.append(entropicDiff)
            #found_regexes = regex_check(os.path.join(path, file), custom_regexes)
            #foundIssues += found_regexes
            #for foundIssue in foundIssues:
            #    print_results(printJson, foundIssue)
            #output["foundIssues"] += foundIssues
    return output

if __name__ == "__main__":
    main()
