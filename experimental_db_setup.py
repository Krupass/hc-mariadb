import mysql.connector
from utils.global_logger import logger
from utils.utils import build_connect_string

# definovane podruhe kvuli cyklickemu importu


def setup_database(args, db_name, sql_file_path='example_db/create_db.sql'):
    default_conn_str = build_connect_string(args)
    try:
        conn = mysql.connector.connect(**default_conn_str)
        conn.autocommit = True
        cur = conn.cursor()
    except mysql.connector.Error as e:
        logger().warning("Failed while connecting to db: " + str(e))
        return 
    # pokud db existuje tak se smaze, aby byl zacatek fresh. db_name je napevno protoze na linuxu je potreba sudo tak aby se nedala vymazat arbitrary db
    cur.execute("SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = %s", (db_name,))
    if cur.fetchone():
        logger().info(f"Database {db_name} already exists. Dropping it.")
        if db_name.isidentifier():
            cur.execute(f"DROP DATABASE IF EXISTS `{db_name}`;")
        else:
            logger().info(f"Error: Database name is not valid: {db_name}")

    
    # vytvor db
    try:
        if db_name.isidentifier():
            cur.execute(f"CREATE DATABASE `{db_name}`;")
            logger().info(f"Database {db_name} created successfully.")
        else:
            logger().info(f"Error: Database {db_name} could not be created because the name is not an identifier.")
    except Exception as e:
        logger().warning(f"Failed to create database {db_name}: " + str(e))



    
    cur.close()
    conn.close()

    args.dbname = db_name
    
    new_db_conn_str = build_connect_string(args)

    
    # pripojeni na nove vytvorenou db
    conn = mysql.connector.connect(**default_conn_str)
    conn.autocommit = True
    cur = conn.cursor()

    
    # spustit create skript
    try:
        with open(sql_file_path, 'r') as file:
            sql_script = file.read()
            cur.execute(sql_script)
        logger().info(f"Database {db_name} setup completed.")
        cur.close()
        conn.close()
    except Exception as e:
        logger().warning(f"Error while executing {sql_file_path} script: {e}")

    

