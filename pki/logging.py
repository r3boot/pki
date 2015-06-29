import sys
import pprint

enable_debug = False

def setup_logging(do_debug):
    global enable_debug
    enable_debug = do_debug

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
    if not enable_debug:
        return
    print_message('[D]', message)

def dump(obj):
    pprint.pprint(obj)

if __name__ == '__main__':
    info('This is an informational message')
    warning('This is a warning message')
    debug('This is a debugging message')
    error('This is an error message (which will return 1)')
