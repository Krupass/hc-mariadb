import argparse
from pathlib import Path
import os
from session import Session
from utils.utils import get_default_mysql_config_path
from utils.utils import get_default_mysql_exec_path
from utils.utils import convert_dict_to_yaml
from utils.global_logger import logger
import pprint

# mozna jeste pridat moznost providnout file s udaji nebo samotny connection string
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", type=Path, help='Select custom path to MySQL configuration.',
                        default=get_default_mysql_config_path())
    parser.add_argument("--dbname", type=str, help="Specify the database name")
    parser.add_argument("--user", type=str, help="Specify the user", default="root")
    parser.add_argument("--password", type=str, help="Specify the password")
    parser.add_argument("--host", type=str, help="Specify the host", default="localhost")
    parser.add_argument("--name", type=str, help="Specify the output document name", default=None)
    parser.add_argument("--custom-latex-engine", type=str, default='pdflatex',
                    help="Allows user to use different latex engine than pdflatex.")
    parser.add_argument("--port", type=str, help="Specify the port", default=3306)
    parser.add_argument('--language', choices=['en', 'cz'], default='en', help='Select the document language (en/cz)')
    parser.add_argument('--no-report', action='store_false', help='Disables converting latex code to pdf')
    parser.add_argument('--setup-db', action='store_true', help='Creates experimental database (development feature)')
    parser.add_argument("--peth", type=Path, help="Select path to mysql.exe", default=get_default_mysql_exec_path())
    return parser.parse_args()


# funkce pro pouziti jako knihony.
def generate_database_documentation(dbname, user='root', password='', host='localhost', port='3306',
                                     path=None, name=None, custom_latex_engine='pdflatex', language='en',
                                     no_report=True, setup_db=False, peth=None):
    path = path or get_default_mysql_config_path()
    peth = peth or get_default_mysql_exec_path()
    args = argparse.Namespace(dbname=dbname, user=user, password=password, host=host, port=port,
                              path=path, name=name, custom_latex_engine=custom_latex_engine,
                              language=language, no_report=no_report, setup_db=setup_db, peth=peth)

    logger().info(f"Generating documentation with the following arguments: {args}")
    sess = Session(args)

def main():
    args = parse_args()
    logger().info(f"Command ran with following arguments: {args}")
    sess = Session(args)

if __name__ == '__main__':
    main()
