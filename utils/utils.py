import os
from utils.global_logger import logger
import mysql.connector
from utils.global_logger import logger
import yaml

def convert_dict_to_yaml(data):
    logger().info("converting data to yaml")
    try:
        yaml_content = yaml.dump(data, default_flow_style=False)
        print(yaml_content)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def sub_array(have, need):
    if not need:
        return True
    for i in need:
        if i not in have:
            return False
    return True

def convert_dict_to_yaml(data):
    logger().info("converting data to yaml")
    try:
        yaml_content = yaml.dump(data, default_flow_style=False)
        print(yaml_content)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def get_mysql_version(base_path):
    if not os.path.exists(base_path):
        logger().warning("MySQL config directory does not exist")
        exit("MySQL config directory does not exist")
    dir = os.listdir(base_path)
    folder = [
        item for item in dir
        if "Server" in item and os.path.isdir(os.path.join(base_path, item))
    ]
    version = ''.join(folder)
    if len(dir) == -1:
        logger().warning("No mysql version installed")
        exit("No mysql version installed")
    return version


def get_default_mysql_config_path():
    if os.name == 'nt':
        base = r"C:\ProgramData\MySQL"
        return str(os.path.join(base, get_mysql_version(base)))
    elif os.name == 'posix':
        return "/etc/mysql/"
    else:
        logger().error("unknown operational system: " + os.name)
        return None

def get_default_mysql_exec_path():
    if os.name == 'nt':
        base = r"C:\Program Files\MySQL"
        server = str(os.path.join(base, get_mysql_version(base)))
        return str(os.path.join(server, "bin"))
    elif os.name == 'posix':
        return "/bin/"
    else:
        logger().info("unknown operational system: " + os.name)
        return None

def get_mysql_version_cmd(base_path):
    import platform, subprocess
    import os
    current_platform = platform.system()

    try:
        if current_platform == 'Windows':
            mysql_cmd = os.path.join(os.path.dirname(base_path), r"bin\mysql")
        else:  # Assuming Linux
            mysql_cmd = 'mysql'

        # Spustit příkaz mysql --version
        version_output = subprocess.check_output([mysql_cmd, '--version'], text=True)

        # Parsování výstupu
        version_lines = version_output.strip().split('\n')
        mysql_version = version_lines[0].split()[5]
        return str(mysql_version)

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to get MySQL version: {str(e)}")
    except FileNotFoundError:
        raise RuntimeError("MySQL executable not found. Ensure it's installed and in your PATH.")


def rewrite_file(filename, content):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))
    file_path = os.path.join(parent_dir, filename)
    with open(file_path, "w") as file:
        file.write(content)

def exec_sql_query(conn, query):

    try:
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        logger().info(f"executed query: \"{query}\" with connection {conn}")
        cursor.close()
        # print(f"result {rows}")
        return rows 
    except mysql.connector.Error as e:
        logger().warning(f"error executing query: \"{query}\" with connection {conn}")
    return None

def build_connect_string(args):
    components = {
        'database': getattr(args, 'dbname', None),
        'user': getattr(args, 'user', None),
        'password': getattr(args, 'password', None),
        'host': getattr(args, 'host', None),
        'port': getattr(args, 'port', None)
    }

    components = {key: value for key, value in components.items() if value is not None}

    logger().info(f"Connection parameters prepared: {components}")
    return components