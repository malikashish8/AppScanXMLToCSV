import xml.etree.ElementTree as ET
import sys

## Set the two paths below before you run
appScanXMLReportPath = ""
csvReportPath = ""

root = ET.parse(appScanXMLReportPath).getroot()
# itd is the dictionary for issueType 
itd = {}
for it in root:
    if (it.tag == 'Results'):
        results = it
for it in results:
    if (it.tag == 'IssueTypes'):
        issuetypes = it

for it in issuetypes:
    if(it.tag == 'IssueType'):
        id = it.attrib['ID']
        tit = {}
        for its in it:
            if(its.tag == 'Severity'):
                tit['severity']=its.text
            if(its.tag == 'RemediationID'):
                tit['remediationID']=its.text
            if(its.tag == 'advisory'):
                for adv in its:
                    if (adv.tag == 'name'):
                        tit['issueName'] = adv.text
                    if (adv.tag == 'cwe'):
                        tit['cweId'] = adv[0].attrib['id']
                        tit['cweTarget'] = adv[0].attrib['target']
        itd[id]=tit
        # adding placeholder cweID and cweTarget if they do not exit to avoid errors KeyError while printing
        if not ( 'cweId' in tit.keys()):
            tit['cweId'] = ''
        if not ( 'cweTarget' in tit.keys()):
            tit['cweTarget'] = ''

print('Parsing complete. Writing to file '+csvReportPath)

sys.stdout = open(csvReportPath,'w')
print('URL,Entity Name,Entity Type,CVSS,Severity,Issue Name,CWE Id,CWE Target')
# now going through issues and pulling respective issueType info and printing
for it in results:
    if (it.tag == 'Issues'):
        issues = it
for it in issues:
    for its in it:
        if(its.tag == 'Url'):
            url = its.text
        if(its.tag == 'CVSS'):
            for itss in its:
                if (itss.tag == 'Score'):
                    cvss = itss.text
        if(its.tag == 'Entity'):
            entityName = its.attrib['Name']
            entityType = its.attrib['Type']
                
    issueTypeID = it.attrib['IssueTypeID']
    print(url,entityName,entityType,cvss,itd[issueTypeID]['severity'],itd[issueTypeID]['issueName'],itd[issueTypeID]['cweId'],itd[issueTypeID]['cweTarget'],\
          sep=',',end='\n',flush=True)
    
