import logging

app_logger = logging.getLogger("app")
app_logger.setLevel(logging.DEBUG)  

stream_handler = logging.StreamHandler()  
file_handler = logging.FileHandler("app.log", mode="a")  #

formatter = logging.Formatter("%(asctime)s [%(levelname)s]: %(message)s", "%Y-%m-%d %H:%M:%S")

stream_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

app_logger.addHandler(stream_handler)
app_logger.addHandler(file_handler)

def logger():
    return app_logger
