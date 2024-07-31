import argparse
import os
import sys
import requests
import json
import yaml
import logging
import subprocess
import re
import csv
from pathlib import Path
 
import concurrent.futures
import threading
import multiprocessing
 
max_workers = min(32, multiprocessing.cpu_count() + 4)
 
def testAPI(url, headers):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    logging.info('Testing API connection...')
    try:
        session.request('GET', f'{url}/api/v2/user/me', headers=headers)
    except requests.exceptions.SSLError as e:
        logging.error('SSL error. Try running with --insecure or adding the invalid cert to your keystore.')
        logging.error(e)
        sys.exit(1)
    except BaseException as e:
        logging.error('Error validating API. Check your url or token.')
        logging.error(e)
        sys.exit(1)
    return
 
def login(url, token):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    logging.info('Logging in...')
    proc = subprocess.Popen(['mapi', '--mayhem-url', url, 'login', token], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    exit_code = proc.wait()
    if exit_code != 0:
        logging.error('Error logging into Mayhem')
        logging.error(f'stdout: {stdout}')
        logging.error(f'stderr: {stderr}')
        sys.exit(1)
    return
 
def parseSpecFile(full_path, specs, base_url, parse_lock, project=None, target=None):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    proc = subprocess.Popen(['mapi', 'describe', 'specification', full_path], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    exit_code = proc.wait()
    if exit_code != 0:
        logging.error('Error parsing spec')
        logging.error(f'stdout: {stdout}')
        logging.error(f'stderr: {stderr}')
        return
    # Python dictionary update is not atomic; need to acquire a lock
    with parse_lock:
        with open(full_path, encoding='utf-8') as cspec:
            contents = cspec.read()
        if full_path.suffix == '.json':
            spec = json.loads(contents)
        elif full_path.suffix == '.yaml':
            spec = yaml.safe_load(contents)
        project = project if project else full_path.parent.stem.replace('_', '-').replace('.', '-')
        target = target if target else full_path.stem.replace('_', '-').replace('.', '-')
        if project not in specs:
            specs[project] = dict()
        if target in specs[project]:
            specs[project][target]['spec_paths'].append(full_path)
        else:
            specs[project][target] = {'spec_paths': [full_path]}
        url = base_url
        if 'servers' in spec:
            if 'url' in spec['servers'][0]:
                url = spec['servers'][0]['url']
        elif 'basePath' in spec:
            url = base_url + spec['basePath']
        specs[project][target]['url'] = url
    return
 
def parsePostmanCollection(full_path, specs, base_url, parse_lock, project=None, target=None):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    proc = subprocess.Popen(['mapi', 'describe', 'specification', full_path], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    exit_code = proc.wait()
    if exit_code != 0:
        logging.error('Error parsing spec')
        logging.error(f'stdout: {stdout}')
        logging.error(f'stderr: {stderr}')
        return
    # Python dictionary update is not atomic; need to acquire a lock
    with parse_lock:
        with open(full_path, encoding='utf-8') as cspec:
            contents = cspec.read()
        if full_path.suffix == '.json':
            spec = json.loads(contents)
        elif full_path.suffix == '.yaml':
            spec = yaml.safe_load(contents)
        project = project if project else re.search(r'https://([^.]+)\.', base_url).group(1)
        target = target if target else full_path.stem.replace('_', '-').replace('.', '-')
        if project not in specs:
            specs[project] = dict()
        if target in specs[project]:
            specs[project][target]['spec_paths'].append(full_path)
        else:
            specs[project][target] = {'spec_paths': [full_path]}
        url = base_url
        if 'servers' in spec:
            if 'url' in spec['servers'][0]:
                url = spec['servers'][0]['url']
        elif 'basePath' in spec:
            url = base_url + spec['basePath']
        specs[project][target]['url'] = url
    return
 
def parseSpecDir(spec_path, specs, base_url, parse_lock, postman, project=None, target=None):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        thread_pool = []
        for root, dirs, files in os.walk(spec_path):
            for f in files:
                full_path = Path(root, f)
                if full_path.suffix == '.json' or full_path.suffix == '.yaml':
                    if postman:
                        thread = executor.submit(parsePostmanCollection, full_path, specs, base_url,
                        parse_lock, project, target)
                    else:
                        thread = executor.submit(parseSpecFile, full_path, specs, base_url, parse_lock, project, target)
                    thread_pool.append(thread)
    return specs
 
def runMayhem(project_api, workspace, project, target, duration, url, spec_path, options, run_lock, dry_run=False):
    logging.debug('Entering ' + sys._getframe().f_code.co_name)
    command = ['mapi', 'run', f'{workspace}/{project}/{target}', duration, spec_path,
        '--url', url]
    if 'headers' in project_api['project']:
        with run_lock:
            for k, v in project_api['project']['headers'].items():
                command.append(f'--header "{k}: {v}"')
    if 'auth_headers' in project_api['project']:
        with run_lock:
            for k, v in project_api['project']['auth_headers'].items():
                command.append(f'--header-auth "{k}: {v}"')
    if 'postman_environment_id' in project_api['project']:
        with run_lock:
            command.append(f'--postman-environment-id {project_api["project"]["postman_environment_id"]["path"]}')
    if 'postman_global_variables' in project_api['project']:
        with run_lock:
            command.append(f'--postman-global-variables {project_api["project"]["postman_global_variables"]["path"]}')
    if 'options' in project_api['project']:
        with run_lock:
            for opt in project_api['project']['options']:
                flag = f'--{opt.replace('_', '-')}'
                setting = project_api['project']['options']['opt']
                command.append(f'{flag} {setting}')
    if options:
        with run_lock:
            command.append(options)
    if not url:
        logging.warn(f'URL necessary to run Mayhem; skipping {workspace}/{project}/{target}')
        return [workspace, project, target, 2]
    if not dry_run:
        try:
            logging.debug(' '.join(command))
            proc = subprocess.Popen(command, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            stdout, stderr = proc.communicate()
            exit_code = proc.wait()
            logging.info(f'stdout: {stdout}')
            logging.info(f'stderr: {stderr}')
            logging.info(f'exit_code: {exit_code}')
            return workspace, project, target, exit_code
        except BaseException as e:
            logging.error(f'Error: {e}')
            logging.error(f'stderr: {stderr}')
            return [workspace, project, target, 3]
    else:
        with run_lock:
            with open('mayhem_commands.txt', 'a') as commandfile:
                commandfile.write(f'echo Target: {project}/{target}\n')
                commandfile.write(' '.join(command))
                commandfile.write('\n\n')
        return [workspace, project, target, 0]
 
if __name__ == '__main__':
 
    if(sys.version_info.major < 3):
        print('Please use Python 3.x or higher')
        sys.exit(1)
 
    parser = argparse.ArgumentParser()
 
    parser.add_argument('--workspace', required=True, type=str, help='The workspace for the project')
    parser.add_argument('--project',  type=str, help='The project name (required if spec is a file)')
    parser.add_argument('--target', type=str, help='The target name (required if spec is a file)')
    parser.add_argument('--spec', required=True, type=str, help='The path to your specification, or a directory of specifications')
    parser.add_argument('--project-config', required=True, type=str, help='The project configuration file')
    parser.add_argument('--mayhem-config', type=str, default='mayhem.config', help='The Mayhem configuration file (defaults to \'mayhem.config\')')
    parser.add_argument('--postman', action='store_true', help='Set to true if using Postman collections')
    parser.add_argument('--mayhem-options', type=str, default='', help='Options you would like to pass to the mapi invocation')
    parser.add_argument('--duration', type=str, default='auto', help='Duration in seconds to run Mayhem (defaults to \'auto\')')
    parser.add_argument('--use-pass', action='store_true', help='Use password store instead of hardcoded tokens')
    parser.add_argument('--serial', action='store_true', help='Kick off mapi runs serially (solves some authentication issues)')
    parser.add_argument('--log', type=str, default='warn', help='Log level (choose from debug, info, warning, error and critical)')
    parser.add_argument('--insecure', action='store_true', help='Disable SSL verification')
    parser.add_argument('--dry-run', action='store_true', help='Dry run; will write run commands to a text file.')


    args = parser.parse_args()
 
    levels = {
        'critical': logging.CRITICAL,
        'error': logging.ERROR,
        'warn': logging.WARNING,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG
    }
 
    session = requests.Session()
    if args.insecure:
        logging.warning('Setting urllib3 session to ignore insecure connections.')
        session.verify = False
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    loglevel = args.log.lower() if (args.log.lower() in levels) else 'warn'
    logging.basicConfig(stream=sys.stderr, level=levels[loglevel], format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    workspace = args.workspace
    project = args.project if args.project else None
    target = args.target if args.target else None
    spec_path = Path(args.spec)
    duration = args.duration
    use_pass = args.use_pass
    serial = args.serial
    postman = args.postman
    project_config = args.project_config
    mayhem_config = args.mayhem_config
    mayhem_options = args.mayhem_options
    dry_run = args.dry_run
 
    with open(project_config, 'r') as config_file:
        config_data = config_file.read()
    project_api = json.loads(config_data)
    project_email = project_api['project']['email']
    project_url = project_api['project']['url']
 
    with open(mayhem_config, 'r') as config_file:
        config_data = config_file.read()
    mayhem_api = json.loads(config_data)
    if use_pass:
        mayhem_api['mayhem']['token'] = subprocess.check_output(mayhem_api['mayhem']['token']).strip().decode('utf-8')
    mayhem_headers = {
        'Content-Type': 'application/json',
        'X-Mayhem-Token': f'token {mayhem_api["mayhem"]["token"]}'
    }
 
    # Set environment
    for k, v in project_api['project']['env'].items():
        os.environ[k] = v
 
    #Ensure API is correct
    testAPI(mayhem_api['mayhem']['url'], mayhem_headers)
    login(mayhem_api['mayhem']['url'], mayhem_api['mayhem']['token'])
 
    specs = dict()
    parse_lock = threading.Lock()
    run_lock = threading.Lock()
    if spec_path.is_file():
        if not project and not target:
            logging.error('Must specify project and target if only providing a single spec file')
            sys.exit(1)
        if postman:
            parsePostmanCollection(spec_path, specs, project_url, parse_lock, project, target)
        else:
            parseSpecFile(spec_path, specs, project_url, parse_lock, project, target)
    elif spec_path.is_dir():
        parseSpecDir(spec_path, specs, project_url, parse_lock, postman, project, target)
    else:
        logging.error(f'Spec {spec_path} must be a file or directory')
        sys.exit(1)
    logging.debug(f'Spec parsing complete. Specs parsed: {len(specs)}')
    concurrent_runs = 1 if serial else max_workers
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_runs) as executor:
        run_pool = []
        for project in specs:
            for target in specs[project]:
                if len(specs[project][target]['spec_paths']) > 1:
                    logging.warning(f'Multiple specs instead of a single spec, skipping {specs[project][target]["spec_paths"]}')
                    continue #TODO: handle unmerged specs
                run = executor.submit(runMayhem, project_api, workspace, project, target, duration, specs[project][target]['url'], str(specs[project][target]['spec_paths'][0]), mayhem_options, run_lock, dry_run)
                run_pool.append(run)
        with open('mayhem_results.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Workspace', 'Project', 'Target', 'Result'])
            for x in concurrent.futures.as_completed(run_pool):
                with run_lock:
                    writer.writerow(x.result())