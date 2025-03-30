from logging import exception, error
from pathlib import Path
import os
import configparser
import mysql.connector
from document_builder import DocumentBuilder
from utils.global_logger import logger
from utils.utils import convert_dict_to_yaml
from utils.errors import InvalidPgHbaConfigFormat
from utils.utils import exec_sql_query
from utils.utils import sub_array
from utils.utils import build_connect_string
import utils.parsers as parse
import pprint
from experimental_db_setup import setup_database


class Session():
    def __init__(self, args):
        self.config_path = args.path
        self.resources = []
        self.conn = None
        self.my_conf = None
        self.privileges = None
        self.document_builder = DocumentBuilder(args.language)
        if args.setup_db == True:
            db_name = "experimental_db"
            setup_database(args, db_name)

        if args.name == None:
            args.name = "{}-{}_{}".format(args.dbname, args.host, args.port)

        try:
            self.conn = mysql.connector.connect(**build_connect_string(args))
            logger().info(f"connection established successfully, connection details: {self.conn}")
            self.resources.append('db_connection')
        except mysql.connector.Error as e:
            logger().warning(f"Error: {e}")
            #vynechat testy ktere potrebuji pripojeni k databazi

        if os.name == 'nt':
            my_conf_path = os.path.join(self.config_path, "my.ini")
        elif os.name == 'posix':
            my_conf_path = os.path.join(self.config_path, "my.cnf")
        else:
            logger().error("unknown operational system: " + os.name)
            my_conf_path = None

        try:
            self.my_conf = parse.parse_mysql_conf(self, my_conf_path)
            logger().info("my.ini configuration file successfully loaded.")
            self.resources.append('my.ini')

        except FileNotFoundError:
            logger().warning(f"config file not found: {my_conf_path}")
        except Exception as e:
            logger().error(f"Error while parsing database configuration: {e}")


        # parse database privileges
        try:
            if self.conn != None:
                self.privileges = parse.parse_database_privileges(self)
            if not bool(self.privileges):
                logger().warning("error while parsing database privileges")
            else:
                self.resources.append('privileges')
                logger().info("succesfully parsed database privileges")
        except e:
                logger().warning(f"error while parsing database privileges {e}")

        # urcit jake testy jsou mozne provest, asi bude potreba pridat nejake flagy do document builder testove struktury. 
        self.test_master()
        self.document_builder.convert_dict_to_yaml()
        if not args.no_report:
            logger().info(f"PDF generating skipped")
        else:
            self.document_builder.generate_latex(args)

        if self.conn != None:
            self.conn.close()

    def test_master(self):
        for number, data in self.document_builder.get_document_builder().items():
            if not sub_array(self.resources, data["required"]):
                data['to_be_tested'] = False
            if data['to_be_tested'] == False:
                continue
            output = data['test_function'](self)
            logger().info(f"ran test function: {data['test_function'].__name__} with output: {output}")
            #if output['compliant'] == False:
            data['config_details'] = str(output['config_details'])
            data['compliant'] = output['compliant']

