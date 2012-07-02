from doctest import DocFileSuite, \
     NORMALIZE_WHITESPACE, IGNORE_EXCEPTION_DETAIL, ELLIPSIS, \
     REPORT_UDIFF

def testsuite():
  return DocFileSuite(
    'README.txt',
    optionflags=NORMALIZE_WHITESPACE | IGNORE_EXCEPTION_DETAIL | ELLIPSIS,
    )
