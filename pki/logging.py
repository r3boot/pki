import sys

def print_message(prefix, message):
    print('{0} {1}'.format(prefix, message))

def info(message):
    print_message('[+]', message)

def warning(message):
    print_message('[W]', message)

def error(message):
    print_message('[E]', message)
    sys.exit(1)

def debug(message):
    print_message('[D]', message)

if __name__ == '__main__':
    info('This is an informational message')
    warning('This is a warning message')
    debug('This is a debugging message')
    error('This is an error message (which will return 1)')
