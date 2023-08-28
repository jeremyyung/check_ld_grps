"""
This module checks the 'groups' OU and compares it with IT's ldap group list
"""
import ldap
from extras.ldap_operations import LdapOperations
from extras.jira_operations import JiraOperations
import re
import json

#Globals (maybe conf vars)
base_dn = "ou=Groups,dc=ops,dc=box,dc=net"
filter_str = "(&(objectClass=posixGroup))"
attrlist = ['cn']
ou_regex = r'ou=.*$(?:(?<=(\w))|(?<=(\W)))'

def loggroups(data, filename=""):
    file = open("rec_" + filename + ".out", 'w')
    if type(data) is dict:
        file.write(json.dumps(data,indent=2))
    else:
        for item in data:
            file.write(item + "\n")

#LOG = get_logger(__file__)

def getLdapGrps() -> {}:
    search_output = queryLdap()
    ldap_dict = {'duplicates':[]}
    dupe_tracker = []
    for item in search_output:
        fqdn = item[0]
        if (fqdn.find('ou=User Groups') < 0): #Ignore stuff in the 'User Goups' ou
            cn = item[1]['cn'][0].decode()
            if dupe_tracker.__contains__(cn):
                ldap_dict['duplicates'].append(cn)
            else:
                dupe_tracker.append(cn)
                ou = re.search(ou_regex,item[0]).group()
                if not ldap_dict.keys().__contains__(ou):
                    ldap_dict[ou] = []
                ldap_dict[ou].append(cn)
    return ldap_dict # {'ou=Groups,dc=ops',dc=box,dc=net':['oc','api','netops'], 'duplicates':[...]}

def queryLdap() -> []:
    ldap_conn = LdapOperations()
    search_output = ldap_conn.connection.search_s(base_dn, ldap.SCOPE_SUBTREE, filterstr=filter_str, attrlist=attrlist)
    return search_output

def getCurentGroups() -> {}:
    jira = JiraOperations()
    confluence_dict = {'group_list':[], 'duplicates':[]}
    ticket_meta = jira.jira.editmeta('NOC-60255')
    cf_allowedvals = ticket_meta['fields']['customfield_20001']['allowedValues']
    group_list = []
    for value_dict in cf_allowedvals:
        value_string = value_dict['value']
        if group_list.__contains__(value_string):
            confluence_dict['duplicates'].append(value_string)
        else:
            group_list.append(value_string)
    confluence_dict['group_list'] = group_list
    return confluence_dict # {'group_list':['ops','role_aws_admin'], 'duplicates':[...]}


def grpCompare(ldap_dict, confluence_dict):
    compare_dict = {'in_both':[],'ldap_only':[],'confluence_only':[],'ldap_duplicates':[],'cnfl_duplicates':[]}
    cnfl_only_list = confluence_dict['group_list'] # Matchin ldap groups will be dropped
    compare_dict['cnfl_duplicates'] = confluence_dict['duplicates']
    for key in ldap_dict.keys():
        if key == 'duplicates':
            compare_dict['ldap_duplicates'] = ldap_dict[key]
            continue
        else:
            ou_grp_list = ldap_dict[key]
            for group in ou_grp_list:
                if confluence_dict['group_list'].__contains__(group):
                    compare_dict['in_both'].append(group)
                else:
                    compare_dict['ldap_only'].append(group)
            cnfl_only_list = list(set(cnfl_only_list) - set(ou_grp_list))
    compare_dict['confluence_only'] = cnfl_only_list
    return compare_dict

def getLdapGrps_test() -> {}:
    file = open('/Users/jyung/stuff/sme_repos/access-request/rec_ldap_groups.out','r')
    return json.load(file)

def getCurentGroups_test() -> {}:
    file = open('/Users/jyung/stuff/sme_repos/access-request/rec_cnfl_groups.out', 'r')
    return json.load(file)


def main():
    # ldap_dict = getLdapGrps_test()
    # confluence_dict = getCurentGroups_test()

    ldap_dict = getLdapGrps()
    confluence_dict = getCurentGroups()

    final_results = grpCompare(ldap_dict, confluence_dict)

    # dumps data to rec_files
    # loggroups(ldap_dict, "ldap_groups")
    # loggroups(confluence_dict, "cnfl_groups")
    # loggroups(final_results, "results")
    print('done')

if __name__ == '__main__':
    main()

# Javascript to print all values in 'LDAP Groups' menu
# var x = document.getElementById('customfield_20001')
# for (i = 0; i < x.length; i++) {
#     console.log(x.options[i].value)
# }