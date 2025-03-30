from session import Session
from utils.utils import get_default_mariadb_config_path
import argparse
from utils.global_logger import logger
def generate_database_documentation(dbname=None, user='root', password='', host='localhost', port='3306',
                                     path=None, name=None, custom_latex_engine='pdflatex', language='en',
                                     no_report=True, setup_db=False):
    path = path or get_default_mariadb_config_path()
    args = argparse.Namespace(dbname=dbname, user=user, password=password, host=host, port=port,
                              path=path, name=name, custom_latex_engine=custom_latex_engine,
                              language=language, no_report=no_report, setup_db=setup_db)

    logger().info(f"Generating documentation with the following arguments: {args}")
    sess = Session(args)
