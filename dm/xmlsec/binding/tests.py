from doctest import DocFileSuite, \
     NORMALIZE_WHITESPACE, IGNORE_EXCEPTION_DETAIL, ELLIPSIS, \
     REPORT_UDIFF

def test_suite():
  return DocFileSuite(
    'README.txt',
    'tests.txt', # additional tests
    optionflags=NORMALIZE_WHITESPACE | IGNORE_EXCEPTION_DETAIL | ELLIPSIS | REPORT_UDIFF,
    )
