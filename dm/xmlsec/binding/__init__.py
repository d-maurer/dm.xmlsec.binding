# Copyright (C) 2012-2024 by Dr. Dieter Maurer <dieter.maurer@online.de>; see 'LICENSE.txt' for details
from ._xmlsec import *
from . import _xmlsec


def initialize(crypto_engine=None):
  """initialize for use of *crypto_engine* (or the default one)."""
  _xmlsec.initialize(crypto_engine)
  transforms_setup()


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


# to be filled in at the end of initialization
transforms = []
transformByHref = {}
transformByName = {}


# fix spelling bug reported by Chris Foresman
addIds = addIDs


# helpers
def transforms_setup():
  def vname(t):
    """the variable name associated with transform *t*."""
    def transform(part):
      if part == "kw": return "KW" # special case
      if part == "exc": return "Excl" # special case
      if part == "tripledes": return "Des3" # special case
      if part.startswith("xpath") or part == "xpointer":
        return "XP" + part[2:]
      if part.startswith("c14n"): return part.upper()
      part = part.capitalize() # standard case
      if part[0].isdigit(): part = "_" + part
      return part
    name = t.name_as_variable
    if name is not None: return name
    name = t.name
    if name == "enveloped-signature": name = "enveloped"
    parts = name.split("-")
    if parts[0].startswith("c14n"): parts.insert(0, "incl")
    t.name_as_variable = name = \
                       "Transform" + "".join(transform(p) for p in  parts)
    return name
  # clean up former state
  md = globals()
  for t in transforms: del md[vname(t)]
  del transforms[:]
  transformByHref.clear()
  transformByName.clear()
  for t in transforms_list():
    md[vname(t)] = t
    transforms.append(t)
    if t.href: transformByHref[t.href] = t
    transformByName[t.name] = t
  _compute_all()


def _compute_all():
  global __all__
  __all__ = [k for k in globals() if not k.startswith("_")]

# generate `__all__` to get the definitions in `_xmlsec` included
_compute_all()
