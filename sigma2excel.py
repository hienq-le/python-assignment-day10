# Day 10: sigma to excel
import re, time, pandas, subprocess, argparse, sys, yaml
# Try to add all options of file command
sigma_compiler = '.\\tools\\sigmac'
args99 = argparse.ArgumentParser(description = 'Convert Sigma rules into SIEM signatures', add_help=False)
args99.add_argument('inputs', type = str, nargs = '*', help = 'Sigma input files (\'-\' for stdin)')
args99.add_argument('-h', '--help', action='store_true', help = 'show this help message and exit')
args99.add_argument('-r', '--recurse', action='store_true', help = 'Use directory as input')
args99.add_argument('-t', '--target', type = str, metavar = '{arcsight,elastalert-dsl,es-dsl,hedera,carbonblack,splunk,ala-rule,mdatp,qradar,fireeye-helix,fortisiem,fieldlist,sentinel-rule,xpack-watcher,grep,sumologic-cse-rule,devo,kibana,limacharlie,chronicle,arcsight-esm,es-qs,es-qs-lr,qualys,stix,kibana-ndjson,sqlite,uberagent,logiq,splunkdm,streamalert,splunkxml,athena,graylog,powershell,sumologic,netwitness,csharp,netwitness-epl,hawk,ee-outliers,dnif,ala,es-rule-eql,logpoint,datadog-logs,es-eql,humio,sysmon,sumologic-cse,lacework,elastalert,sql,es-rule,crowdstrike,opensearch-monitor}', help = 'Output target format')
args99.add_argument('-l', '--lists', '--target-list', action='store_true', help = 'List available output target formats')
args99.add_argument('-L', '--lists-file-after-date', type = str, metavar = 'DATE', help = 'List yml files which are modified/created after the date')
args99.add_argument('-c', '--config', type = str, metavar = 'CONFIG', help = 'Configurations with field name and index mapping for target environment')
args99.add_argument('-o', '--output', type = str, metavar = 'OUTPUT', help = 'Output file or filename prefix if multiple files are generated')
args99.add_argument('-of', '--output-fields', type = str, metavar = 'OUTPUT-FIELDS', help = 'Enhance your output with additional fields from the Sigma rule')
args99.add_argument('-oF', '--output-format', type = str, metavar = '{json,yaml}', help = 'Specify output format')
args99.add_argument('--print0', action='store_true', help = 'Delimit results by NUL-character')
args99.add_argument('-O', '--backend-option', type = str, metavar = 'BACKEND_OPTION', help = 'Options and switches that are passed to the backend. NOTE: This option is ignored from January 1, 2023.')
args99.add_argument('-d', '--defer-abort', action='store_true', help = 'Don\'t abort on parse or conversion errors, proceed with next rule')
args99.add_argument('-I', '--ignore-backend-errors', action='store_true', help = 'Only return error codes for parse errors and ignore errors for rules that cause backend errors')
args99.add_argument('-v', '--verbose', action='store_true', help = 'Be verbose')
args99.add_argument('-D', '--debug', action='store_true', help = 'Debugging output')
# Check if sigmac in tools exists or not
try:
    main_file = open(sigma_compiler, 'r')
    main_file.close()
except FileNotFoundError:
    print('Error!')
    exit()
args999 = args99.parse_args()
args998 = sys.argv
args997 = ['python']
args998[0] = sigma_compiler
for abxyz in args998:
    args997.append(abxyz)
# If sample command meets i.e. splunk database, xlsx output; run in 10-minute loop, otherwise run once
if (len(re.findall('-t', ''.join(args997))) > 0 or len(re.findall('--target', ''.join(args997))) > 0) and len(re.findall('splunk', ''.join(args997))) > 0 and (len(re.findall('-c', ''.join(args997))) > 0 or len(re.findall('--config', ''.join(args997))) > 0) and (len(re.findall('-o', ''.join(args997))) > 0 or len(re.findall('--output', ''.join(args997))) > 0) and len(re.findall('.xlsx', ''.join(args997))) > 0:
    a888 = 0
    while a888 == 0:
        a888 = 0
        output_file_name = args997[len(args997) - 1]
        args997.pop(len(args997) - 1)
        args997.pop(len(args997) - 1)
        file_name = args997[len(args997) - 1]
        if len(re.findall(r"\\", args997[len(args997) - 1])) > 0:
            file_name4 = file_name.split("\\")
            file_name2 = file_name4[len(file_name4) - 1]
        elif len(re.findall("/", args997[len(args997) - 1])) > 0:
            file_name4 = file_name.split("/")
            file_name2 = file_name4[len(file_name4) - 1]
        else:
            file_name2 = file_name
        ated_string = subprocess.run(args997, shell=True, stdout=subprocess.PIPE).stdout.decode('utf8')
        ated_string = ated_string.replace("\"", "\\\"")
        ated_string = ated_string.replace("\\", "\\\\")
        ated_string = ated_string.replace("\\\\", "\\")
        try:
            config_file = open(args997[len(args997) - 2], "r")
            yml_file_to_read = open(file_name, "r")
            yml_cursor = yaml.safe_load(yml_file_to_read)
            config_file.close()
            yml_file_to_read.close()
        except FileNotFoundError:
            print("Error!")
            exit()
        yml_database = pandas.json_normalize(yml_cursor)
        test_dict68 = '[{\"File Name\":\"' + file_name2 + '\",\"Title\":\"' + ''.join(yml_database.loc[0]['title']) + '\",\"Description\":\"' + ''.join(yml_database.loc[0]['description']) + '\",\"Technique\":\"' + ''.join(yml_database.loc[0]['falsepositives']) + '\",\"Query\":\"' + ated_string + '\"}]'
        data_frame_to_export_to_excel = pandas.read_json(test_dict68, orient="records")
        try:
            data_frame_to_export_to_excel.to_excel(output_file_name,index=None, header=True)
        except PermissionError:
            print("Error!")
            time.sleep(600)
            continue        
        time.sleep(600)
else:
    print(subprocess.run(args997, shell=True, stdout=subprocess.PIPE).stdout.decode('utf8'))