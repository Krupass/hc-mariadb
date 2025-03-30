class InvalidPgHbaConfigFormat(Exception):
    """Raised when the pg_hba.conf file has an invalid format."""
    pass

class FileNotFound(Exception):
    """Exception raised when the file is not found."""

    def __init__(self, path, message="File not found"):
        self.path = path
        self.message = f"{message}: {path}"
        super().__init__(self.message)