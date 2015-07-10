import nose
import sys

sys.path.insert(0, '../')


from pkilib import utils


def test_enddate_type():
    assert(isinstance(utils.gen_enddate(10), str)) == True


def test_enddate_length():
    assert(len(utils.gen_enddate(10)) == 15) == True


def test_enddate_string():
    assert(utils.gen_enddate('somerandomstring')) == None


def test_enddate_empty():
    assert(utils.gen_enddate(None)) == None
