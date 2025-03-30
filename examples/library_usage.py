import sys
import os
current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.insert(0, parent_dir)


from dbaudit import generate_database_documentation

user = "root"
password = "test"  # Prázdný řetězec pro heslo
host = "localhost"  # Předpokládá se výchozí hodnota
port = "3306"  # Předpokládá se výchozí hodnota
name = "report"
setup_db = True  # Příznak pro nastavení databáze

# Volání funkce pro generování dokumentace
generate_database_documentation(user=user, password=password, name=name, setup_db=setup_db)