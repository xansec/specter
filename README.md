# Mayhem Specter
 
This takes a swagger/ folder, consumes all API specs, and kicks off a run for each API. Current behavior is parallel with up to 32 threads running simultaneously. Can also run serially.
 
Example:
```
py specter.py --workspace devsecops --duration 30 --dry-run --spec swagger/
```
 
## usage
 
```
usage: specter.py [-h] --workspace WORKSPACE [--project PROJECT] [--target TARGET] --spec SPEC [--project-config PROJECT_CONFIG] [--mayhem-config MAYHEM_CONFIG] [--mayhem-options MAYHEM_OPTIONS]
                  [--duration DURATION] [--use-pass] [--serial] [--log LOG] [--insecure] [--dry-run]
 
options:
  -h, --help            show this help message and exit
  --workspace WORKSPACE
                        The workspace for the project
  --project PROJECT     The project name (required if spec is a file)
  --target TARGET       The target name (required if spec is a file)
  --spec SPEC           The path to your specification, or a directory of specifications
  --project-config PROJECT_CONFIG
                        The project configuration file (defaults to 'project.config')
  --mayhem-config MAYHEM_CONFIG
                        The Mayhem configuration file (defaults to 'mayhem.config')
  --mayhem-options MAYHEM_OPTIONS
                        Options you would like to pass to the mapi invocation
  --duration DURATION   Duration in seconds to run Mayhem (defaults to 'auto')
  --use-pass            Use UNIX password store instead of hardcoded tokens
  --serial              Kick off mapi runs serially (solves some authentication issues)
  --log LOG             Log level (choose from debug, info, warning, error and critical)
  --insecure            Disable SSL verification
  --dry-run             Dry run; will write run commands to a text file.
  ```