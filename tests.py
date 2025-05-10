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
        if not user.strip().startswith("mariadb."):
            if ssl_type.strip().lower() == "x509" or ssl_type.strip().lower() == "specified" or ssl_type.strip().lower() == "any":
                compliant = True
            else:
                compliant = False
                was_compliant_false = True
                if ssl_type.strip() == "":
                    parsed_data[user] = [host, "$\\times$"]
                else:
                    parsed_data[user] = [host, ssl_type]

    if not parsed_data == {}:
        details = details + latex_g.detail_to_latex(parsed_data, "User", "Host", "SSL Type", False) + "\n"

    parsed_data = {}

    require_secure_transport = sess.my_conf.get("mariadb_require_secure_transport", None)
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

    ssl_cipher = sess.my_conf.get("mariadb_ssl_cipher", None)
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
                FROM INFORMATION_SCHEMA.INNODB_TABLESPACES_ENCRYPTION;"""
    compliant = None
    was_compliant_false = False
    details = ""

    result = exec_sql_query(con, query)
    parsed_data = {}

    if result:
        for row in result:
            name, encryption_scheme, current_key_id = row
            if encryption_scheme == 0 or encryption_scheme == "0":
                compliant = False
                was_compliant_false = True
            elif encryption_scheme == 1 or encryption_scheme == "1":
                compliant = True
            else:
                logger().warning("Unknown InnoDB encryption scheme {}.".format(encryption_scheme))

            parsed_data[name] = [str(encryption_scheme), str(current_key_id)]
        details = "Records in information\\_schema.innodb\\_tablespaces\\_encryption table: " + latex_g.detail_to_latex(parsed_data, "Name", "Encryption scheme", "Key ID", True) + "\n"
    else:
        details = "\\textbf{No record in information\\_schema.innodb\\_tablespaces\\_encryption table. }"
        logger().error("No individual tables are encrypted at rest.")

    parsed_data = {}

    innodb_encrypt_tables = sess.my_conf.get("mariadb_innodb_encrypt_tables", None)
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

    innodb_encrypt_log = sess.my_conf.get("mariadb_innodb_encrypt_log", None)
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

    innodb_encrypt_temporary_tables = sess.my_conf.get("mariadb_innodb_encrypt_temporary_tables", None)
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
    insecure_methods = ["mysql_native_password", "mysql_old_password"]
    warning_methods = ["named_pipe", "unix_socket"]
    secure_methods = ["ed25519", "gssapi"]
    user_plugins_sorted = {}
    compliant = None
    was_false = False
    details = ""

    for user, values in mariadb_auth_methods.items():
        if not user.strip().startswith("mariadb."):
            host, plugin = values

            if plugin in insecure_methods:
                user_plugins_sorted[user] = [plugin, "insecure"]
                compliant = False
                was_false = True
            elif plugin in warning_methods:
                user_plugins_sorted[user] = [plugin, "warning"]
                compliant = False
                was_false = True
            elif plugin in secure_methods:
                user_plugins_sorted[user] = [plugin, "secure"]
                compliant = True
            else:
                user_plugins_sorted[user] = [plugin, "unknown"]
                compliant = False
                was_false = True


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
            insecure_users[user] = [plugin, "warning"]
            compliant = False

        elif plugin == "named_pipe":
            insecure_users[user] = [plugin, "warning"]
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
            parsed_data[name] = [dll, ret]

        details = details + latex_g.detail_to_latex(parsed_data, "Name", "Library name", "Returns", True)
        compliant = False
        was_compliant_false = True
    else:
        compliant = True
        details = details + "No functions in mysql.func table. "

    parsed_data = {}

    query = """SELECT Grantee, Table_schema, Privilege_type 
               FROM information_schema.schema_privileges
               WHERE Table_schema = 'mysql' 
               AND Privilege_type IN ('INSERT', 'DELETE');"""
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

        details = details + "\\textbf{Users with direct change privileges over \\texttt{mysql} database:} " + latex_g.detail_to_latex(parsed_data, "Grantee", "Table schema", "Privileges", True)
        compliant = False
        was_compliant_false = True
    else:
        compliant = True
        details = details + "No users with direct change privileges over \\texttt{mysql} database."

    if was_compliant_false:
        compliant = False

    return {
        'compliant': compliant,
        'config_details': details
    }

def test_file_access(sess):
    compliant = None
    was_compliant_false = None
    details = ""
    con = sess.conn
    parsed_data = {}

    secure_file_priv = sess.my_conf.get("mariadb_secure_file_priv", None)
    if secure_file_priv is None:
        query = """SHOW VARIABLES LIKE 'secure_file_priv';"""
        result = exec_sql_query(con, query)
        variable, secure_file_priv = result[0]

    parsed_data["secure_file_priv"] = secure_file_priv
    secure_file_priv = secure_file_priv.strip().lower()

    if secure_file_priv == "" or secure_file_priv == "null" or secure_file_priv is None:
        compliant = False
        was_compliant_false = True
        details = "\\textbf{MariaDB server has unrestricted write/read access to files. }"
    elif "/" in secure_file_priv or "\\" in secure_file_priv:
        compliant = True
        details = "MariaDb server has restricted read/write access to files. "
    else:
        logger().warning("Secure file privilege untracked value: {}.".format(secure_file_priv))

    local_infile = sess.my_conf.get("mariadb_local_infile", None)
    if local_infile is None:
        query = """SHOW VARIABLES LIKE 'local_infile';"""
        result = exec_sql_query(con, query)
        variable, local_infile = result[0]

    parsed_data["local_infile"] = local_infile
    local_infile = local_infile.strip().lower()

    if local_infile == "on":
        compliant = False
        was_compliant_false = True
        details = details + "\\textbf{Local is supported for \\texttt{LOAD DATA INFILE} statements. }"
    elif local_infile == "off":
        compliant = True
        details = details + "Local loading data will fail with error message. "
    else:
        logger().warning("Local infile untracked value: {}.".format(local_infile))

    details = details + latex_g.mariadb_conf_dict_to_latex_table(parsed_data, "Variable", "Value", True)

    query = """SELECT User, Host, File_priv
                   FROM mysql.user
                   WHERE File_priv = 'Y';"""

    result = exec_sql_query(con, query)
    parsed_data = {}

    if result == "":
        compliant = True
        details = details + " No user has privilege to read/write to files."
    else:
        compliant = False
        was_compliant_false = True
        details = details + " Users in following table have privilege to read/write to files."
        for user, host, file_priv in result:
            if user not in parsed_data:
                parsed_data[user] = [host, file_priv]

        details = details + "\n" + latex_g.detail_to_latex(parsed_data, "User", "Host", "File_priv", True)

    if was_compliant_false:
        compliant = False

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

    general_log = sess.my_conf.get("mariadb_general_log", None)
    if general_log is None:
        query = """SHOW VARIABLES LIKE 'general_log';"""
        result = exec_sql_query(con, query)
        variable, general_log = result[0]

    parsed_data["general_log"] = general_log
    general_log = general_log.strip().lower()

    if general_log == "off":
        compliant = True
        details = details + "General logging is turned off. "
    elif general_log == "on":
        compliant = False
        wasFalse = True
        details = details + "\\textbf{General logging is turned on and could expose sensitive information. } "
    else:
        logger().warning("General logging untracked value: {}.".format(general_log))

    slow_query_log = sess.my_conf.get("mariadb_slow_query_log", None)
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

    long_query_time = sess.my_conf.get("mariadb_long_query_time", None)
    if long_query_time is None:
        query = """SHOW VARIABLES LIKE 'long_query_time';"""
        result = exec_sql_query(con, query)
        variable, long_query_time = result[0]

    parsed_data["long_query_time"] = float(long_query_time).__round__(6)

    if float(long_query_time) > 10:
        compliant = False
        wasFalse = True
        details = details + "\\textbf{Long query time is too long.} "
    else:
        compliant = True
        details = details + "Long query time is set reasonably. "

    log_bin = sess.my_conf.get("mariadb_log_bin", None)
    if log_bin is None:
        query = """SHOW VARIABLES LIKE 'log_bin';"""
        result = exec_sql_query(con, query)
        variable, log_bin = result[0]

    parsed_data["log_bin"] = log_bin
    log_bin = log_bin.strip().lower()

    if log_bin == "on":
        bin_log = True
    elif log_bin == "off":
        bin_log = False
    else:
        bin_log = False
        logger().warning("Binary logging untracked value: {}.".format(log_bin))

    encrypt_binlog = sess.my_conf.get("mariadb_encrypt_binlog", None)
    if encrypt_binlog is None:
        query = """SHOW VARIABLES LIKE 'encrypt_binlog';"""
        result = exec_sql_query(con, query)
        variable, encrypt_binlog = result[0]

    parsed_data["encrypt_binlog"] = encrypt_binlog
    encrypt_binlog = encrypt_binlog.strip().lower()

    if bin_log == True and encrypt_binlog == "on":
        compliant = True
        details = details + "Binary logging is turned on. Encryption of binary logs is turned on."
    elif bin_log == True and encrypt_binlog == "off":
        compliant = False
        wasFalse = True
        details = details + "Binary logging is turned on. " + "\\textbf{Encryption of binary logs is turned off.} "
    elif bin_log == False and encrypt_binlog == "on":
        compliant = False
        wasFalse = True
        details = details + "\\textbf{Binary logging is turned off. } " + "Encryption of binary logs is turned on."
    elif bin_log == False and encrypt_binlog == "off":
        compliant = False
        wasFalse = True
        details = details + "\\textbf{Binary logging is turned off. Encryption of binary logs is turned off.} "
    else:
        logger().warning("Encrypt binlog untracked value: {}.".format(encrypt_binlog))

    if wasFalse == True:
        compliant = False

    return {
        'compliant': compliant,
        'config_details': details + "\n" + latex_g.mariadb_conf_dict_to_latex_table(parsed_data, "Variable", "Value", True),
    }

def test_ssl(sess):
    compliant = None
    was_compliant_False = False
    con = sess.conn
    details = ""

    parsed_data = {}

    have_ssl = sess.my_conf.get("mariadb_have_ssl", None)
    if have_ssl is None:
        query = """SHOW VARIABLES LIKE 'have_ssl';"""
        result = exec_sql_query(con, query)
        variable, have_ssl = result[0]

    parsed_data["have_ssl"] = have_ssl
    have_ssl = have_ssl.strip().lower()

    if have_ssl == "yes":
        compliant = True
        details = details + "MariaDB server supports TLS and TLS is enabled. "
    elif have_ssl == "no":
        compliant = False
        was_compliant_False = True
        details = details + "\\textbf{MariaDB server does not support TLS. } "
    elif have_ssl == "disabled":
        compliant = False
        was_compliant_False = True
        details = details + "\\textbf{MariaDB server supports TLS but TLS is not enabled. } "
    else:
        logger().warning("Have SSL untracked value: {}.".format(have_ssl))

    ssl_ca = sess.my_conf.get("mariadb_ssl_ca", None)
    if ssl_ca is None:
        query = """SHOW VARIABLES LIKE 'ssl_ca';"""
        result = exec_sql_query(con, query)
        variable, ssl_ca = result[0]

    if ssl_ca.strip() == "":
        parsed_data["ssl_ca"] = "$\\times$"
    else:
        parsed_data["ssl_ca"] = ssl_ca
    ssl_ca = ssl_ca.strip().lower()

    if ssl_ca == "" or ssl_ca == "NULL" or ssl_ca == "null":
        compliant = False
        was_compliant_False = True
        details = details + "\\textbf{No path in ssl\\_ca to file that contains trusted Certificate Authorities for TLS. } "
    elif "." in ssl_ca or "/" in ssl_ca or "\\" in ssl_ca:
        compliant = True
        details = details + "Ssl\\_ca contains path to file that contains trusted Certificate Authorities for TLS. "
    else:
        logger().warning("SSL Certificate Authority untracked value: {}.".format(ssl_ca))

    ssl_cert = sess.my_conf.get("mariadb_ssl_cert", None)
    if ssl_cert is None:
        query = """SHOW VARIABLES LIKE 'ssl_cert';"""
        result = exec_sql_query(con, query)
        variable, ssl_cert = result[0]

    if ssl_cert.strip() == "":
        parsed_data["ssl_cert"] = "$\\times$"
    else:
        parsed_data["ssl_cert"] = ssl_cert
    ssl_cert = ssl_cert.strip().lower()

    if ssl_cert == "" or ssl_cert == "NULL" or ssl_cert == "null":
        compliant = False
        was_compliant_False = True
        details = details + "\\textbf{No path in ssl\\_cert to the certificate for TLS. } "
    elif "." in ssl_cert or "/" in ssl_cert or "\\" in ssl_cert:
        compliant = True
        details = details + "Ssl\\_cert contains path to the certificate for TLS. "
    else:
        logger().warning("SSL Certificate untracked value: {}.".format(ssl_cert))

    ssl_key = sess.my_conf.get("mariadb_ssl_key", None)
    if ssl_key is None:
        query = """SHOW VARIABLES LIKE 'ssl_key';"""
        result = exec_sql_query(con, query)
        variable, ssl_key = result[0]

    if ssl_key.strip() == "":
        parsed_data["ssl_key"] = "$\\times$"
    else:
        parsed_data["ssl_key"] = ssl_key
    ssl_key = ssl_key.strip().lower()

    if ssl_key == "" or ssl_key == "NULL" or ssl_key == "null":
        compliant = False
        was_compliant_False = True
        details = details + "\\textbf{No path in ssl\\_key to the private key for TLS. } "
    elif "." in ssl_key or "/" in ssl_key or "\\" in ssl_key:
        compliant = True
        details = details + "Ssl\\_key contains path to the private key for TLS. "
    else:
        logger().warning("SSL Key untracked value: {}.".format(ssl_key))

    if was_compliant_False:
        compliant = False
    details = details + latex_g.mariadb_conf_dict_to_latex_table(parsed_data, "Variable", "Value", False)

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