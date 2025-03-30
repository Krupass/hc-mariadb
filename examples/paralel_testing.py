import sys
import os
from concurrent.futures import ThreadPoolExecutor

current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.insert(0, parent_dir)

from dbaudit import generate_database_documentation
from experimental_db_setup import setup_database
from collections import namedtuple
from pathlib import Path

Args = namedtuple('Args', ['path', 'dbname', 'user', 'password', 'host', 'name', 'custom_latex_engine', 'port', 'language', 'no_report', 'setup_db'])

args = Args(
    path=Path('C:/Program Files/MariaDB/data'),
    dbname='experimental_paralel_db',
    user='root',
    password='test',
    host='localhost',
    name='paralel_testing_example',
    custom_latex_engine='pdflatex',
    port='3306',
    language='en',
    no_report=True,
    setup_db=True
)


def generate_doc(name, dbname, args):
    generate_database_documentation(user=args.user, password=args.password, name=name, dbname=dbname, host=args.host, port=args.port)

tasks = [
    (args.name, args.dbname),
    (args.name + "_2", args.dbname + "_2" if args.dbname else None),
    (args.name + "_3", args.dbname + "_3" if args.dbname else None)
]

# Vytvoření databází pro test
setup_database(args, args.dbname)
setup_database(args, args.dbname + "_2" )
setup_database(args, args.dbname + "_3" )

# Spuštění úloh paralelně
with ThreadPoolExecutor() as executor:
    futures = [executor.submit(generate_doc, task[0], task[1], args) for task in tasks]
    for future in futures:
        future.result()  