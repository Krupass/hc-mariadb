import os
import pprint
import re
import mysql.connector
import requests

from latex_generator import escape_latex
from utils.global_logger import logger
from utils.utils import exec_sql_query
from utils.utils import get_mariadb_version_cmd as get_mariadb_version
import utils.parsers as parser
import latex_generator as latex_g

def test_transit_encryption(sess):
    con = sess.conn
    query = "SELECT user, host, ssl_type FROM mysql.user;"
    compliant = None
    was_compliant_false = False
    details = ""

    result = exec_sql_query(con, query)

    parsed_data = {}

    for row in result:
        user, host, ssl_type = row
        if not user.strip().startswith("mysql."):
            if ssl_type.strip().lower() == "x509" or ssl_type.strip().lower() == "ssl" or ssl_type.strip().lower() == "any":
                compliant = True
            else:
                compliant = False
                was_compliant_false = True
                if ssl_type.strip() == "":
                    parsed_data[user] = [host, "$\\times$"]
                else:
                    parsed_data[user] = [host, ssl_type]

    if not parsed_data == {}:
        details = latex_g.detail_to_latex(parsed_data, "User", "Host", "SSL Type", False) + "\n"

    parsed_data = {}

    require_secure_transport = sess.my_conf.get("mysqld_require_secure_transport", None)
    if require_secure_transport is None:
        query = """SHOW VARIABLES LIKE 'require_secure_transport';"""
        result = exec_sql_query(con, query)
        variable, require_secure_transport = result[0]

    parsed_data["require_secure_transport"] = require_secure_transport
    require_secure_transport = require_secure_transport.strip().lower()

    if require_secure_transport == "on":
        compliant = True
        details = details + "Clients are required to use some form of secure transport. "
    elif require_secure_transport == "off":
        compliant = False
        was_compliant_false = True
        details = details + "\\textbf{Clients aren't required to use form of secure transport. } "
    else:
        logger().warning("Require secure transport untracked value: {}.".format(require_secure_transport))

    ssl_cipher = sess.my_conf.get("mysqld_ssl_cipher", None)
    if ssl_cipher is None:
        query = """SHOW VARIABLES LIKE 'ssl_cipher';"""
        result = exec_sql_query(con, query)
        variable, ssl_cipher = result[0]

    if ssl_cipher.strip() == "":
        parsed_data["ssl_cipher"] = "$\\times$"
    else:
        parsed_data["ssl_cipher"] = ssl_cipher.strip()
    ssl_cipher = ssl_cipher.strip().lower()

    if ssl_cipher == "none" or ssl_cipher is None or ssl_cipher == "null" or ssl_cipher == "":
        compliant = False
        was_compliant_false = True
        details = details + "\\textbf{No SSL encryption cipher specified. } "
    else:
        compliant = True
        details = details + "List of permissible encryption ciphers specified. "

    if was_compliant_false is True:
        compliant = False

    details = details + "\n" + latex_g.mariadb_conf_dict_to_latex_table(parsed_data, "Variable", "Value", False)

    return {
        'compliant' : compliant,
        'config_details' : details
    }

def test_rest_encryption(sess):
    con = sess.conn
    query = """SELECT NAME, ENCRYPTION_SCHEME, CURRENT_KEY_ID 
                FROM INFORMATION_SCHEMA.INNODB_TABLESPACES_ENCRYPTION"""
    compliant = None
    was_compliant_false = False
    details = ""

    result = exec_sql_query(con, query)
    parsed_data = {}

    if result:
        for row in result:
            name, encryption_scheme, current_key_id = row
            if encryption_scheme.strip() == 1 or encryption_scheme.strip() == "1":
                compliant = True
            else:
                compliant = False
                was_compliant_false = True

            parsed_data[name] = [encryption_scheme, current_key_id]
        details = latex_g.detail_to_latex(parsed_data, "Name", "Encryption scheme", "Key ID", True) + "\n"
    else:
        logger().error("No individual tables are encrypted at rest.")

    parsed_data = {}

    innodb_encrypt_tables = sess.my_conf.get("mysqld_innodb_encrypt_tables", None)
    if innodb_encrypt_tables is None:
        query = """SHOW VARIABLES LIKE 'innodb_encrypt_tables';"""
        result = exec_sql_query(con, query)
        variable, innodb_encrypt_tables = result[0]

    parsed_data["innodb_encrypt_tables"] = innodb_encrypt_tables
    innodb_encrypt_tables = innodb_encrypt_tables.strip().lower()

    if innodb_encrypt_tables == "on":
        compliant = True
        details = details + "Table encryption is enabled for all new and existing tables that have the ENCRYPTED table option set to DEFAULT, but allows unencrypted tables to be created. "
    elif innodb_encrypt_tables == "off":
        compliant = False
        was_compliant_false = True
        details = details + "\\textbf{Table encryption is disabled for all new and existing tables that have the ENCRYPTED table option set to DEFAULT. } "
    elif innodb_encrypt_tables == "force":
        compliant = True
        details = details + "Table encryption is enabled for all new and existing tables that have the ENCRYPTED table option set to DEFAULT and doesn't allow unencrypted tables to be created. "
    else:
        logger().warning("Innodb encrypt tables untracked value: {}.".format(innodb_encrypt_tables))

    innodb_encrypt_log = sess.my_conf.get("mysqld_innodb_encrypt_log", None)
    if innodb_encrypt_log is None:
        query = """SHOW VARIABLES LIKE 'innodb_encrypt_log';"""
        result = exec_sql_query(con, query)
        variable, innodb_encrypt_log = result[0]

    parsed_data["innodb_encrypt_log"] = innodb_encrypt_log
    innodb_encrypt_log = innodb_encrypt_log.strip().lower()

    if innodb_encrypt_log == "on":
        compliant = True
        details = details + "Encryption of the InnoDB redo log is enabled. "
    elif innodb_encrypt_log == "off":
        compliant = False
        was_compliant_false = True
        details = details + "\\textbf{Encryption of the InnoDB redo log is disabled. } "
    else:
        logger().warning("Innodb encrypt log untracked value: {}.".format(innodb_encrypt_log))

    innodb_encrypt_temporary_tables = sess.my_conf.get("mysqld_innodb_encrypt_temporary_tables", None)
    if innodb_encrypt_temporary_tables is None:
        query = """SHOW VARIABLES LIKE 'innodb_encrypt_temporary_tables';"""
        result = exec_sql_query(con, query)
        variable, innodb_encrypt_temporary_tables = result[0]

    parsed_data["innodb_encrypt_temporary_tables"] = innodb_encrypt_temporary_tables
    innodb_encrypt_temporary_tables = innodb_encrypt_temporary_tables.strip().lower()

    if innodb_encrypt_temporary_tables == "on":
        compliant = True
        details = details + "Automatic encryption of the InnoDB temporary tablespace is enabled. "
    elif innodb_encrypt_temporary_tables == "off":
        compliant = False
        was_compliant_false = True
        details = details + "\\textbf{Automatic encryption of the InnoDB temporary tablespace is disabled. } "
    else:
        logger().warning("Innodb encrypt temporary tables untracked value: {}.".format(innodb_encrypt_temporary_tables))

    if was_compliant_false is True:
        compliant = False

    return {
        'compliant' : compliant,
        'config_details' : details + latex_g.mariadb_conf_dict_to_latex_table(parsed_data, "Variable", "Value", False)
    }


def test_insecure_auth_methods(sess):
    mariadb_auth_methods = parser.parse_auth_methods(sess)
    insecure_methods = ["mysql_native_password", "mysql_old_password", "named_pipe", "unix_socket"]
    warning_methods = []
    secure_methods = ["ed25519", "gssapi", "pam", "parsec"]
    user_plugins_sorted = {}
    compliant = None
    was_false = False

    for user, values in mariadb_auth_methods.items():
        if not user.strip().startswith("mysql."):
            host, plugin = values

            if plugin in insecure_methods:
                user_plugins_sorted[user] = [plugin, "insecure"]
                compliant = False
                was_false = True
            elif plugin in warning_methods:
                user_plugins_sorted[user] = [plugin, "warning"]
            elif plugin in secure_methods:
                user_plugins_sorted[user] = [plugin, "secure"]
                compliant = True
            else:
                user_plugins_sorted[user] = [plugin, "unknown"]
                compliant = False
                was_false = True



    details = ""
    if bool(user_plugins_sorted):
        details = latex_g.detail_to_latex(user_plugins_sorted, "User", "Plugin", "Security", True)

    if was_false is True:
        compliant = False

    return {
        'compliant' : compliant,
        'config_details' : details
    }


def test_trust_authentication(sess):
    mariadb_auth_methods = parser.parse_auth_methods(sess)
    mariadb_empty_passwords = parser.parse_empty_passwords(sess)
    insecure_users = {}
    compliant = None

    for user, values in mariadb_auth_methods.items():
        host, plugin = values

        if plugin == "unix_socket":
            insecure_users[user] = [plugin, "insecure"]
            compliant = False

        elif plugin == "named_pipe":
            insecure_users[user] = [plugin, "insecure"]
            compliant = False

    for user, values in mariadb_empty_passwords.items():
        host, plugin, auth_string = values

        insecure_users[user] = [plugin, "No password or NULL"]
        compliant = False

    details = ""
    if bool(insecure_users):
        details = details + "\n" + latex_g.detail_to_latex(insecure_users, "User", "Plugin", "Password", True)

    
    return {
        'compliant' : compliant,
        'config_details' : details
    }

def test_software_version(sess):
    installed_mariadb_version = "Unknown"
    latest_mariadb_version = "Unknown"

    try:
        con = sess.conn
        query = "SELECT VERSION();"
        result = exec_sql_query(con, query)
        installed_mariadb_version = result[0][0].split("-")
    except mysql.connector.Error as err:
        logger().warning("Error getting MariaDB version from SQL query: {}".format(err))

        installed_mariadb_version = get_mariadb_version(sess.peth)

    url = "https://mariadb.com/downloads/community/community-server/"
    try:
        response = requests.get(url)
    except Exception as e:
        response = None
        logger().warning("Error getting MariaDB version from URL: {}".format(e))
    if response:
        if response.status_code == 200:
            match = re.search(r'<select[^>]*id="version-select-community_server"[^>]*>(.*?)</select>', response.text, re.DOTALL)
            if match:
                content = match.group(1)
                options = re.findall(r'<option[^>]*value="([^"]*)".*?>(.*?)</option>', content)
                latest_mariadb_version = options[0][1].split("-")[0]
        else:
            latest_mariadb_version = "11.7.2"

    logger().info("Installed MariaDB version: {}".format(installed_mariadb_version[0]))
    logger().info("Latest MariaDB version: {}".format(latest_mariadb_version))

    is_updated = installed_mariadb_version[0] == latest_mariadb_version
    details = ""
    if is_updated:
        details = "({}).".format(latest_mariadb_version)
    else:
        details = "{} instead of latest version {}".format(installed_mariadb_version[0], latest_mariadb_version)

    return {
        'compliant' : is_updated,
        'config_details' : "\\textbf{ " + details + "}"
    }

def test_user_permissions(sess):
    return {
        'compliant': False,
        'config_details': latex_g.privilege_dict_to_latex_table(sess.privileges)
    }

def test_user_defined_functions(sess):
    compliant = None
    was_compliant_false = False
    details = ""
    con = sess.conn

    parsed_data = {}

    query = """SELECT * FROM mysql.func;"""
    result = exec_sql_query(con, query)

    if result:

        for row in result:
            name, ret, dll, type = row
            parsed_data[name] = [dll, type]

        details = details + latex_g.detail_to_latex(parsed_data, "Name", "Library name", "Type", True)
        compliant = False
        was_compliant_false = True
    else:
        compliant = True
        details = details + "No functions in mysql.func table. "

    parsed_data = {}

    query = """SELECT Grantee, Table_schema, Privilege_type 
               FROM information_schema.schema_privileges
               WHERE Table_schema = 'mysql' 
               AND Privilege_type IN ('INSERT', 'UPDATE', 'DELETE');"""
    result = exec_sql_query(con, query)

    if result:
        for row in result:
            grantee, table_schema, privilege = row
            if grantee in parsed_data:
                privileges = parsed_data[grantee][1].split(", ")
                privileges.append(privilege)
                parsed_data[grantee][1] = ", ".join(privileges)
            else:
                parsed_data[grantee] = [table_schema, privilege]

        details = details + "\\textbf{Users with direct change privileges over mysql schema:} " + latex_g.detail_to_latex(parsed_data, "Grantee", "Table schema", "Privileges", True)
        compliant = False
        was_compliant_false = True
    else:
        compliant = True
        details = details + "No users with direct change privileges over mysql schema."

    if was_compliant_false:
        compliant = False

    return {
        'compliant': compliant,
        'config_details': details
    }

def test_file_access(sess):
    compliant = None
    details = ""
    con = sess.conn
    query = """SELECT @@global.secure_file_priv;"""

    directory = exec_sql_query(con, query)

    if directory[0][0] == "None":
        if directory[0][0] == "":
            logger().warning("Unrestricted write/read access to files.")
            compliant = False
            details = "\\textbf{SQL server has unrestricted write/read access to files.}"
        elif directory[0][0] == "NULL" or None:
            logger().info("No access to files.")
            compliant = True
            details = "SQL server has no access to files."
        else:
            logger().info("Access to files in directory: {}".format(directory[0][0]))
            compliant = True
            details = "SQL server has access to files in directory {}.".format(latex_g.escape_latex(directory[0][0]))
    else:
        logger().error("No result in file access.")


    query = """SELECT User, Host, File_priv
                   FROM mysql.user
                   WHERE File_priv = 'Y';"""

    result = exec_sql_query(con, query)
    parsed_data = {}

    if result == "":
        details = details + " No user has privilege to read/write to files."
    else:
        details = details + " Users in following table have privilege to read/write to files."
        for user, host, file_priv in result:
            if user not in parsed_data:
                parsed_data[user] = [host, file_priv]

        details = details + "\n" + latex_g.detail_to_latex(parsed_data, "User", "Host", "File_priv", True)

    return {
        'compliant': compliant,
        'config_details': details
    }

def test_log_conf(sess):
    compliant = None
    wasFalse = False
    details = ""
    con = sess.conn

    parsed_data = {}

    general_log = sess.my_conf.get("mysqld_general_log", None)
    if general_log is None:
        query = """SHOW VARIABLES LIKE 'general_log';"""
        result = exec_sql_query(con, query)
        variable, general_log = result[0]

    parsed_data["general_log"] = general_log
    general_log = general_log.strip().lower()

    if general_log == "on":
        compliant = True
        details = details + "General logging is on. "
    elif general_log == "off":
        compliant = False
        wasFalse = True
        details = details + "\\textbf{General logging is off.} "
    else:
        logger().warning("General logging untracked value: {}.".format(general_log))

    log_raw = sess.my_conf.get("mysqld_log_raw", None)
    if log_raw is None:
        query = """SHOW VARIABLES LIKE 'log_raw';"""
        result = exec_sql_query(con, query)
        if result:
            variable, log_raw = result[0]

            parsed_data["log_raw"] = log_raw
            log_raw = log_raw.strip().lower()

    if log_raw == "on":
        compliant = False
        wasFalse = True
        details = details + "\\textbf{Passwords can be exposed because of the log\\_raw setting.} "
    elif log_raw == "off":
        compliant = True
        details = details + "Log\\_raw setting doesn't expose passwords. "
    else:
        logger().warning("Log\\_raw setting untracked value: {}.".format(log_raw))

    slow_query_log = sess.my_conf.get("mysqld_slow_query_log", None)
    if slow_query_log is None:
        query = """SHOW VARIABLES LIKE 'slow_query_log';"""
        result = exec_sql_query(con, query)
        variable, slow_query_log = result[0]

    parsed_data["slow_query_log"] = slow_query_log
    slow_query_log = slow_query_log.strip().lower()

    if slow_query_log == "on":
        compliant = True
        details = details + "Slow query logging is on. "
    elif slow_query_log == "off":
        compliant = False
        wasFalse = True
        details = details + "\\textbf{Slow query logging is off.} "
    else:
        logger().warning("Slow query logging untracked value: {}".format(slow_query_log))

    long_query_time = sess.my_conf.get("mysqld_long_query_time", None)
    if long_query_time is None:
        query = """SHOW VARIABLES LIKE 'long_query_time';"""
        result = exec_sql_query(con, query)
        variable, long_query_time = result[0]

    parsed_data["long_query_time"] = float(long_query_time).__round__(1)

    if float(long_query_time) > 10:
        compliant = False
        wasFalse = True
        details = details + "\\textbf{Long query time is too long.} "
    else:
        compliant = True
        details = details + "Long query time is set reasonably. "

    innodb_strict_mode = sess.my_conf.get("mysqld_innodb_strict_mode", None)
    if innodb_strict_mode is None:
        query = """SHOW VARIABLES LIKE 'innodb_strict_mode';"""
        result = exec_sql_query(con, query)
        variable, innodb_strict_mode = result[0]

    parsed_data["innodb_strict_mode"] = innodb_strict_mode
    innodb_strict_mode = innodb_strict_mode.strip().lower()

    if innodb_strict_mode == "on":
        compliant = True
        details = details + "Innodb strict logging is on."
    elif innodb_strict_mode == "off":
        compliant = False
        wasFalse = True
        details = details + "\\textbf{Innodb strict logging is off.}"
    else:
        logger().warning("InnoDB strict logging untracked value: {}".format(innodb_strict_mode))

    if wasFalse == True:
        compliant = False

    return {
        'compliant': compliant,
        'config_details': details + "\n" + latex_g.mariadb_conf_dict_to_latex_table(parsed_data, "Variable", "Value", True),
    }

def test_verbose_errors(sess):
    compliant = None
    details = ""
    con = sess.conn
    variable = None
    query = """SHOW VARIABLES LIKE 'log_error_verbosity';"""

    result =  exec_sql_query(con, query)

    if result:
        variable, value = result[0]

    if variable == "log_error_verbosity":
        if value == "1":
            compliant = True
            details = "\\textbf{Current level of error verbosity is 1, which is recommended setting.}"
        elif value == "2":
            compliant = True
            details = ("\\textbf{Current level of error verbosity is 2, which is compromise between security and usability. "
                       "Warnings are logged, consider reducing verbosity.}")
        elif value == "3":
            compliant = False
            details = ("\\textbf{Current level of error verbosity is 3, which is insecure setting. "
                       "Detailed logs could expose sensitive information.}")
        else:
            logger().warning("Unknown log_error_verbosity value: {}".format(value))
    else:
        logger().warning("Unknown variable in verbose errors testing: {}".format(variable))

    return {
        'compliant': compliant,
        'config_details': details
    }

def test_ssl(sess):
    compliant = None
    con = sess.conn
    query = """SHOW VARIABLES 
                LIKE 'have_ssl';"""

    result = exec_sql_query(con, query)

    variable, value = result[0]

    if variable == 'have_ssl':
        if value == 'YES':
            details = "SSL is allowed."
            compliant = True
        else:
            details = "SSL isn't active."
            compliant = False
    else:
        details = ""
        logger().warning("Variable 'have_ssl' not found.")

    query = """SHOW VARIABLES
                WHERE Variable_name 
                IN ('ssl_ca', 'ssl_cert', 'ssl_key');"""

    result = exec_sql_query(con, query)

    latex_table = "\\begin{center}\n\\begin{tabular}{|l|l|}\n\\hline\n"
    latex_table += "\\textbf{Variable name} & \\textbf{Value} \\\\ \\hline\n"

    for variable, value in result:
        if variable == 'ssl_ca':
            if value == '' or value == 'NULL':
                details = details + (" SSL Certificate Authority (CA) is missing or not configured. "
                                     "MariaDB will not validate client certificates, which may reduce security.")
                if compliant:
                    compliant = False
            else:
                details = details + (" SSL Certificate Authority (CA) is correctly configured. "
                                     "MariaDB can verify client certificates.")
        elif variable == 'ssl_cert':
            if value == '' or value == 'NULL':
                details = details + (" SSL certificate is missing or not configured. "
                                     "MariaDB cannot establish encrypted connections.")
                if compliant:
                    compliant = False
            else:
                details = details + " SSL certificate is correctly set."
        elif variable == 'ssl_key':
            if value == '' or value == 'NULL':
                details = details + (" SSL private key is missing or not configured. "
                                     "MariaDB cannot use SSL for encrypted connections.")
                if compliant:
                    compliant = False
            else:
                details = details + " SSL private key is correctly set."

        latex_row = f"{latex_g.escape_latex(variable)} & {latex_g.escape_latex(value)} \\\\ \\hline\n"
        latex_table += latex_row

    latex_table += "\\end{tabular}"
    latex_table += "\\end{center}\n"

    details = details + "\n" + latex_table

    return {
        'compliant': compliant,
        'config_details': details
    }

def test_super(sess):
    con = sess.conn
    query = """SELECT User, Host, Super_priv
               FROM mysql.user
               WHERE Super_priv = 'Y';"""

    result = exec_sql_query(con, query)
    parsed_data = {}

    if result:
        for user, host, super_priv in result:
            if user not in parsed_data:
                parsed_data[user] = [host, super_priv]

        details = latex_g.detail_to_latex(parsed_data, "User", "Host", "SUPER", True)
        compliant = False
    else:
        compliant = True
        details = ""

    return {
        'compliant': compliant,
        'config_details': details
    }