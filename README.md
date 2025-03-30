# Overview

This project focuses on evaluating the security configuration of a MariaDB database system, ensuring it aligns with best practices. The tool analyzes the setup and presents its findings in a clear and structured manner.
The generated report provides essential insights to help identify and rectify potential misconfigurations.

To execute the security checks, ensure that a MariaDB database instance is running. Database credentials can be supplied using command-line arguments.

For tests requiring access to configuration files, specify their location using the `--path` flag. If no path is provided, the default configuration directory will be used.  

If the necessary database connection or configuration files are not accessible, the tool will automatically skip tests dependent on these resources.

## Get the script

```sh
git clone https://gitlab.com/hc-tools1/hc-mariadb
cd $_
```

## Prerequisites
#### **Before running the automatic test check if you have all the prerequisites!**

- **Python** - Download and install the latest stable version of Python from https://www.python.org/downloads/
- **MariaDB Server** - Check if your server is setup and running.
- **Custom LaTeX Engine** (default: pdflatex) - Ensure that a LaTeX engine is installed on your system, as the script require it for generating reports.
- **Python Libraries** - Install the required Python libraries.
Following commands iterate over `dependencies` file stored in this directory and performs `pip install` in order to install them.
##### Windows CMD
```
for /F %i in (dependencies) do pip install %i
```
##### Windows Powershell
```
Get-Content dependencies | ForEach-Object { pip install $_ }
```
#### Bash
```
xargs -a dependencies -r pip install
```

## Running the script

For Non-existing database :
```sh
python .\main.py --setup-db --user <username> --password <password> --host <host> --port <port>
```

In case that all values are default you can use just:
```sh
python .\main.py --setup-db 
```

For already existing database:
```sh
python .\main.py --dbname <dbname> --user <username> --password <password> --host <host> --port <port>
```

## Flags
  -p \<PATH\>, --path \<PATH\>  Select custom path to MariaDB configuration.
  
  --dbname \<DBNAME\>       Specify the database name
  
  --user \<USER\>            Specify the user (default: root)
  
  --password \<PASSWORD\>    Specify the password
  
  --host \<HOST\>            Specify the host (default: localhost)
  
  --port \<PORT\>            Specify the port (default: 3306)

  --custom-latex-engine \<CUSTOM-LATEX-ENGINE\> Converts LaTeX input to pdf format (default: pdflatex)

  --setup-db            Creates experimental database (development feature)

## Dependencies
- python 3+
- pdflatex (optional)

### Python Libraries
- argparse
- configparser
- logging
- requests
- pyyaml
- matplotlib
- mysql-connector-python
- pylatex
- psutil
