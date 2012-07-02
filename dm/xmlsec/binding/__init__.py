# Copyright (C) 2012 by Dr. Dieter Maurer <dieter@handshake.de>; see 'LICENSE.txt' for details
from _xmlsec import *

def dsig(tag):
  """`lxml` tag designator for *tag* in DSig namespace."""
  return "{%s}%s" % (DSigNs, tag)

def enc(tag):
  """`lexml` tag designator for *tag* in XMLEnc namespace."""
  return "{%s}%s" % (EncNs, tag)

def findNode(node, tag):
  """return the first element with *tag* at or below *node*."""
  if hasattr(node, "getroot"): node = node.getroot()
  if node.tag == tag: return node
  return node.find(".//" + tag)

# generate `__all__` to get the class definitions in `_xmlsec` included
__all__ = list(k for k in globals().iterkeys() if not k.startswith("_"))
