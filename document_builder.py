import tests
import subprocess
import yaml
from utils.global_logger import logger
from tests import *
from utils.utils import rewrite_file
import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt
import uuid
from utils.utils import get_mariadb_version_cmd as get_mariadb_version


class DocumentBuilder:
    def __init__(self, language):
        self.sev = {"info":"info", "low": "low", "medium": "medium", "high": "high"}
        self.document_builder = self.get_document_by_lang(language)
        self.yaml_data = None
        self.technical_details = None

    def get_document_builder(self):
        return self.document_builder

    def convert_dict_to_yaml(self):
        yaml_data = yaml.dump(self.get_document_builder(), default_flow_style=False) 
        self.yaml_data = yaml_data

    def generate_latex(self, args):
        self.generate_intro(args)
        self.generate_technical_details_section()
        self.generate_tested_ares_table()
        self.generate_summary()
        self.latex_to_pdf(args)
        
    def latex_to_pdf(self, args):
        engine = args.custom_latex_engine
        output_name = args.name  # Název výstupního souboru bez přípony .pdf
        logger().info(f"generating pdf from latex using {engine}")
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir, 'latex_template')

        try:
            # Přidání přepínačů pro nastavení názvu výstupního souboru a cílové složky
            result = subprocess.run([engine, '-jobname', output_name, 'main.tex'], cwd=file_path)
            logger().info(f"Subprocess didn't except, result: {result}")
        except subprocess.CalledProcessError as e:
            logger().error(f"Could not run {engine}: ", e)
        except FileNotFoundError:
            logger().error(f"Command {engine} not found")
        except Exception as e:
            logger().error(e)


    
    def generate_summary(self):
        data = yaml.load(self.yaml_data, Loader=yaml.FullLoader)
        current_dir = os.path.dirname(os.path.abspath(__file__))


        # zajisteni ze pri multhreadingu nebude race condition
        current_dir = os.path.dirname(__file__)
        while True:
            unique_id = uuid.uuid4()
            file_name = f'severity_graph_{unique_id}.png'
            file_path = os.path.join(current_dir, f'latex_template/{file_name}')
            if not os.path.exists(file_path):
                break  

        severity_count = {'low': 0, 'medium': 0, 'high': 0, 'info': 0}
        total_count = 0
        for key, item in data.items():
            severity = item.get('severity', '').lower()
            compliant = item.get('compliant', False)
            to_be_tested = item.get('to_be_tested', '')
            if severity in severity_count and compliant == False:
                if to_be_tested:
                    severity_count[severity] += 1
                    total_count += 1

        plt.figure(figsize=(10, 6))
        plt.bar(severity_count.keys(), severity_count.values(), color=['green', 'yellow', 'red', 'blue'])
        plt.xlabel('Severity Level')
        plt.ylabel('Number of Findings')
        plt.title('Findings by Severity Level')
        plt.savefig(file_path)  

        latex = "\\section{Summary}\n"
        latex += f"""During the test total of {total_count} misconfigurations were found.
                    
                    Following figure shows graphically number of misconfigurations and their impact:
                    \n
                    """
        latex +="\\includegraphics[width=\\textwidth]{" + file_name + "}"
        rewrite_file("latex_template/summary.tex", latex)


    def generate_tested_ares_table(self):
        data = yaml.load(self.yaml_data, Loader=yaml.FullLoader)
        latex_table = """
        \\section{Tested areas}
        \\begin{center}
        \\begin{tabular}{ | m{1cm} | m{15em} | m{1.5cm} | m{1.7cm} | m{1.5cm}|}
            \\hline
            \\textbf{No.} & \\textbf{area of interest} & \\textbf{tested} & \\textbf{compliant} &\\textbf{severity}\\\\
            \\hline
        """
        for key, value in data.items():
            #print("VALS " + str(value["compliant"]) )
            tested = "$\\checkmark$" if value["to_be_tested"] else "$\\times$"
            compliant = "$\\checkmark$" if value["compliant"] else "$\\times$"
            severity = value["severity"]
            latex_table += f"    {key} & {latex_g.escape_latex(value['subsection'])} & {tested} & {compliant} & {latex_g.escape_latex(severity)} \\\\\\hline\n"

        latex_table += """
        \\end{tabular}
        \\end{center}
        """
        rewrite_file("latex_template/tested_areas.tex", latex_table)

    def generate_intro(self, identity):
        import platform
        import psutil
        import subprocess

        cpu_info = platform.processor() or "N/A"
        cpu_cores = psutil.cpu_count(logical=False)
        ram_info = psutil.virtual_memory().total // (1024**3)  
        disk_info = psutil.disk_usage('/').total // (1024**3)  
        os_info = f"{platform.system()} {platform.release()}"
        latex_preamble = f"""
            \\newpage
            \\section*{{Tested System Information}}
            \\noindent Path to MariaDB Configuration: {latex_g.escape_latex(str(identity.path))} \\\\
            Database Name: {latex_g.escape_latex(str(identity.dbname))} \\\\
            User: {latex_g.escape_latex(str(identity.user))} \\\\
            Host: {latex_g.escape_latex(str(identity.host))} \\\\
            Port: {latex_g.escape_latex(str(identity.port))} \\\\
            CPU: {latex_g.escape_latex(str(cpu_info))} ({cpu_cores} cores) \\\\
            RAM: {latex_g.escape_latex(str(ram_info))} GB \\\\
            Storage Size: {latex_g.escape_latex(str(disk_info))} GB \\\\
            Operating System: {latex_g.escape_latex(str(os_info))} \\\\
            MariaDB Version: {latex_g.escape_latex(get_mariadb_version(identity.peth))}
                """
        rewrite_file("latex_template/intro.tex", latex_preamble)

    def generate_technical_details_section(self):
        # print(self.yaml_data)
        #data = yaml.safe_load(self.yaml_data)
        data = yaml.load(self.yaml_data, Loader=yaml.FullLoader)
        latex_code = "\\section{Technical details}\n"
        for item in data.values():
            to_be_tested = item.get('to_be_tested')
            if to_be_tested == False:
                continue
            subsection = item.get('subsection', '')
            description = item.get('description', '')
            compliant = item.get('compliant', False)
            show_config = item.get('show_config', False)
            config_details = item.get('config_details', '')
            recommendation = item.get('recommendation', '')
            
            latex_code += "\\subsection{" + latex_g.escape_latex(subsection) + "}\n"
            
            latex_code += "\\paragraph{Description} " + latex_g.escape_latex(description) + "\n\n"
            
            if compliant:
                compliant_desc = item.get('description_compliant', '')
                latex_code += latex_g.escape_latex(compliant_desc) + "\n"
                #latex_code += config_details + "\n"
            else:
                noncompliant_desc = item.get('description_noncompliant', '')
                latex_code += latex_g.escape_latex(noncompliant_desc) + "\n"
                #latex_code += config_details + "\n"
            
            # printne configuracni detaily, pokud neni compliant nebo pokud je to specificky nastavene (to je pro pripady ze je potreba 
            # ukazat konfiguraci v compliant i noncompliant pripadech)

            if show_config or compliant == False:
                #print("thru")
                latex_code += config_details + "\n"
            else:
                latex_code += "\n"
            
            if recommendation:
                latex_code += "\\paragraph{Recommendation} " + latex_g.escape_latex(recommendation) + "\n\n"
            else:
                latex_code += "\n\n"

        rewrite_file("latex_template/technical_details.tex", latex_code)
        self.technical_details = latex_code


    def get_document_by_lang(self, language):
            document_data = {
                "en": {
                    1: {
                        "subsection": "Encryption at transit",
                        "description": "This test verifies that database enforces encryption to ensure safe communication that cannot be eavesdropped. "
                        "Improper configuration of encryption could lead to violation of CIA triade.",
                        "compliant": False,
                        "show_config": True,
                        "required": ['db_connection'],
                        "to_be_tested": True,
                        "severity": self.sev["low"],
                        "description_noncompliant": "This test found that following users are not configured to "
                                                 "ensure encrypted communication:",
                        "description_compliant": "This test found that all users enforce encrypted comunication.",
                        "config_details": "",
                        "recommendation":"We recoment implementing secure data transit with encryption.",
                        "test_function": tests.test_transit_encryption
                    },
                    2: {
                        "subsection": "Encryption at rest",
                        "description": "This test verifies that database tablespaces are encrypted. If the value is 'Y', "
                                       "it indicates that the tablespace is encrypted, while 'N' indicates that the "
                                       "tablespace is not encrypted. The test will list all tablespaces along with their "
                                       "encryption status.",
                        "compliant": False,
                        "show_config": True,
                        "required": ['db_connection'],
                        "to_be_tested": True,
                        "severity": self.sev["low"],
                        "description_noncompliant": "\\textbf{Not all tablespaces are encrypted}.",
                        "description_compliant": "All tablespaces are encrypted.",
                        "config_details": "",
                        "test_function": tests.test_rest_encryption
                    },
                    3: {
                        "subsection":   "Insecure authentication plugins",
                        "description":  "This test examines the 'mysql.user' table for outdated authentication plugins. Specifically, "
                                        "it identifies the use of 'mysql_old_password', which is highly insecure and has been removed "
                                        "in modern MariaDB versions, and 'mysql_native_password', which relies on the SHA1 hashing algorithm"
                                        " and is considered less secure than newer authentication plugins such as 'caching_sha2_password'. "
                                        "While 'mysql_native_password' is still widely used, its reliance on SHA1 makes it vulnerable to "
                                        "cryptographic weaknesses, and its use is discouraged in favor of stronger authentication plugins.",
                        "compliant": False,
                        "show_config": True,
                        "required": ['db_connection'],
                        "to_be_tested": True,
                        "severity": self.sev["medium"],
                        "description_compliant": "\\textbf{Database uses configuration that enforce secure authentication methods}",
                        "description_noncompliant": "\\textbf{Database doesn't enforce secure authentication methods}",
                        "config_details": "",
                        "test_function": tests.test_insecure_auth_methods
                    },
                    4: {
                        "subsection":   "Trust authentication",
                        "description":  "Trust authentication permits unrestricted access to the database for any user without requiring a password. "
                                        "This configuration poses a significant security risk, as it allows potentially unauthorized individuals "
                                        "to gain access to sensitive data and perform unauthorized actions within the database. "
                                        "Utilizing trust authentication undermines the fundamental principle of access control and compromises "
                                        "the confidentiality, integrity, and availability of the database.",
                        "compliant": False,
                        "show_config": True,
                        "required": ['db_connection'],
                        "to_be_tested": True,
                        "severity": self.sev["high"],
                        "description_compliant": "\\textbf{User cannot connect without authentication.}",
                        "description_noncompliant": "\\textbf{Database allows some users to connect without password.}",
                        "config_details": "",
                        "test_function": tests.test_trust_authentication
                    },
                    5: {
                        "subsection": "Latest version of MariaDB",
                        "description": "This test verifies whether the database uses the latest software version. "
                                       "Outdated versions could contain security vulnerabilities that could be used "
                                       "by an attacker to compromise the database.",
                        "compliant": False,
                        "show_config": True,
                        "required": ['db_connection'],
                        "to_be_tested": True,
                        "severity": self.sev["low"],
                        "description_compliant": "\\textbf{Database uses latest version of MariaDB }",
                        "description_noncompliant": "\\textbf{Database uses outdated version of MariaDB }",
                        "config_details": "",
                        "test_function": tests.test_software_version                    
                    },
                    6: {
                            "subsection":   "Permissions test",
                            "description":  "The following table provides a comprehensive overview of all privileges assigned within the specified database. "
                                            "This information is crucial for evaluating the access control mechanisms in place and identifying potential "
                                            "security vulnerabilities. A thorough permissions audit ensures that only authorized users have appropriate access "
                                            "rights, minimizing the risk of unauthorized data access or modification. "
                                            "Following table contains users and their permission on database tables:",
                            "compliant": False,
                            "show_config": True,
                            "required": ['privileges'],
                            "to_be_tested": True,
                            "severity": self.sev["info"],
                            "description_compliant": "\\textbf{}",
                            "description_noncompliant": "\\textbf{}",
                            "config_details": "",
                            "test_function": tests.test_user_permissions
                    },
                    7: {
                            "subsection": "User defined functions",
                            "description": "The purpose of this test is to verify that the MariaDB server is properly "
                                           "secured against potential abuse of user defined functions. The test will inspect the contents of the mysql.func table, "
                                           "which stores information about any custom functions that have been loaded into the server."
                                           " Additionally, the test will check schema privileges table for users with privileges over mysql schema.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['db_connection'],
                            "to_be_tested": True,
                            "severity": self.sev["info"],
                            "description_compliant": "\\textbf{}",
                            "description_noncompliant": "\\textbf{}",
                            "config_details": "",
                            "test_function": tests.test_user_defined_functions
                    },
                    8: {
                            "subsection": "File system access",
                            "description": "Tests that the MariaDB server is properly configured to restrict file system "
                                           "access and that only authorized users have the FILE privilege.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['db_connection'],
                            "to_be_tested": True,
                            "severity": self.sev["medium"],
                            "description_compliant": "\\textbf{}",
                            "description_noncompliant": "\\textbf{}",
                            "config_details": "",
                            "test_function": tests.test_file_access
                    },
                    9: {
                            "subsection": "Log configuration",
                            "description": "Verifies that the the logging configuration of a MariaDB server prevents "
                                           "sensitive data exposure and ensure compliance with security best practices.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['my.ini', 'db_connection'],
                            "to_be_tested": True,
                            "severity": self.sev["info"],
                            "description_compliant": "\\textbf{}",
                            "description_noncompliant": "\\textbf{}",
                            "config_details": "",
                            "test_function": tests.test_log_conf
                    },
                    10: {
                            "subsection": "Client side errors",
                            "description": "This test checks the error verbosity setting on the MariaDB server to "
                                           "determine if error messages are securely configured. The error verbosity"
                                           " variable controls the level of detail included in error logs. A higher "
                                           "verbosity level may expose sensitive information, making it easier "
                                           "for attackers to gather insights about the database structure, users, or "
                                           "potential vulnerabilities.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['db_connection'],
                            "to_be_tested": True,
                            "severity": self.sev["low"],
                            "description_compliant": "Client-side error logging is properly configured. "
                                                     "Only critical errors are recorded in the logs, minimizing "
                                                     "the risk of information leakage.\n",
                            "description_noncompliant": "Client-side error logging is too verbose. "
                                                        "The current setting allows warnings or informational "
                                                        "messages to be recorded, which may expose sensitive details.\n",
                            "config_details": "",
                            "test_function": tests.test_verbose_errors
                    },
                    11: {
                            "subsection": "Configuration of SSL",
                            "description": "This test verifies whether MariaDB has SSL enabled. Additionally, it ensures "
                                           "that the required SSL variables are correctly configured.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['db_connection'],
                            "to_be_tested": True,
                            "severity": self.sev["medium"],
                            "description_compliant": "\\textbf{}",
                            "description_noncompliant": "\\textbf{}",
                            "config_details": "",
                            "test_function": tests.test_ssl
                    },
                    12: {
                            "subsection": "SUPER privileges",
                            "description": "This test checks which users have the SUPER privilege in the MariaDB database. "
                                           "The test queries the mysql.user table.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['db_connection'],
                            "to_be_tested": True,
                            "severity": self.sev["info"],
                            "description_compliant": "There are no users with \\textbf{SUPER} privileges in the database. "
                                                     "This improves security by preventing unauthorized changes to "
                                                     "global settings and system operations. If administrative access "
                                                     "is required, consider granting more specific privileges instead "
                                                     "of \\textbf{SUPER}.",
                            "description_noncompliant": "The following users have \\textbf{SUPER} privileges, which "
                                                        "grant them extensive control over the MariaDB server. This "
                                                        "privilege allows modifying global settings, managing "
                                                        "replication, and terminating processes. It should be "
                                                        "restricted to administrative users only. Consider "
                                                        "reviewing and revoking \\textbf{SUPER} where it is not necessary.",
                            "config_details": "",
                            "test_function": tests.test_super
                    },
                },
            }
                

            return document_data[language]