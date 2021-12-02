import tempfile
import itertools as IT
import os

# From https://stackoverflow.com/questions/13852700/create-file-but-if-name-exists-add-number
def uniquify(path, sep = ''):
    def name_sequence():
        count = IT.count()
        yield ''
        while True:
            yield '{s}{n:d}'.format(s = sep, n = next(count))
    orig = tempfile._name_sequence
    with tempfile._once_lock:
        tempfile._name_sequence = name_sequence()
        path = os.path.normpath(path)
        dirname, basename = os.path.split(path)
        filename, ext = os.path.splitext(basename)
        fd, filename = tempfile.mkstemp(dir = dirname, prefix = filename, suffix = ext)
        tempfile._name_sequence = orig
    return filename

def store_request(request):
    filename = uniquify('./unit_test/lz_hub_test_requests/req')
    try:
        with open(filename, "wb") as reqfile:
            reqfile.write(request)
    except Exception as e:
        print("ERROR TEST STORE REQ: %s" %str(e))