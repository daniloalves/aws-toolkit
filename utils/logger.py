import logging
from os import environ

AWS_TOOLKIT = environ['AWS_TOOLKIT_PATH']
LOG_ROOT_DIR = f'{AWS_TOOLKIT}/logs'

def logger_aws_toolkit(log_level='info'):
    logger_level = logging.INFO

    if log_level == 'debug':
        log_level = logging.DEBUG
        
    APPLICATION_LOG_FILE = f'{LOG_ROOT_DIR}/aws_toolkit.log'

    logger_default_format = logging.Formatter(fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logger_default_level = logger_level

    logger_application = logging.getLogger('aws_toolkit')
    logger_application.setLevel(logger_level)

    logger_application_hdlr = logging.FileHandler(filename=APPLICATION_LOG_FILE)
    logger_application_hdlr.setLevel(logger_default_level)
    logger_application_hdlr.setFormatter(logger_default_format)
    logger_application.addHandler(logger_application_hdlr)

    logger_application.info('logger_aws_toolkit loaded.')
    return logger_application
