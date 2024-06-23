#cython: embedsignature=True, language_level=3
# Copyright (C) 2012-2024 by Dr. Dieter Maurer <dieter.maurer@online.de>; see 'LICENSE.txt' for details
"""Cython generated binding to `xmlsec`.

We probably should have `with nogil` for all `xmlsec` functions working
on larger structures.

Should carefully use `const` and `unsigned` in the `xmlsec` prototypes
and cast as necessary to avoid compile time warnings.
"""

from libc cimport stdlib
from libc.string cimport const_char, strlen
from cxmlsec cimport *
from etreepublic cimport import_lxml__etree, _Document, _Element, pyunicode, \
     elementFactory
from tree cimport xmlDocCopyNode, xmlFreeNode, xmlNode, xmlDoc, \
     xmlDocGetRootElement, xmlReplaceNode, _isElement

cdef extern from "stdio.h":
  ctypedef struct FILE
  FILE *stdout

cdef extern from "libxml/tree.h":
  int xmlDocDump(FILE * f, xmlDoc*)
  

from logging import getLogger as _getLogger
_logger = _getLogger(__name__)


import_lxml__etree()


__error_callback = None


cdef void _error_callback(char *filename, int line, char *func, char *errorObject, char *errorSubject, int reason, char * msg) noexcept with gil:
  if __error_callback is None: return

  try:
    __error_callback(
      filename=to_text(filename, "unknown"),
      line=line,
      func=to_text(func, "unknown"),
      errorObject=to_text(errorObject, "unknown"),
      errorSubject=to_text(errorSubject, "unknown"),
      reason=reason,
      msg=to_text(msg, ""),
      )
  except:
    _logger.exception("XMLSec error callback raised exception")


def set_error_callback(cb):
  """define *cb* as error callback (and return the old one).

  *cb* must have a signature compatible with
  `(filename, line, func, errorObject, errorSubject, reason, msg)`.
  *line* and *reason* are integers, the remaining parameters are strings

  `None` disables the callback.
  """
  global __error_callback
  rv = __error_callback
  __error_callback = cb
  return rv

def get_error_callback():
  """return the current error callback."""
  return __error_callback



class Error(Exception):
  """an `xmlsec` error."""

class VerificationError(Error):
  """signature verification failed."""



def init():
  """base `xmlsec` initialization.

  Usually, you would use `initialize` rather than this low level function.
  """
  if xmlSecInit() != 0:
    raise Error("xmlsec initialization failed")

def cryptoAppInit(name=None):
  """initialize crypto engine *name* (or the deault engine).

  Usually, you would use `initialize` rather than this low level function.
  """
  name = bytes_or_none(name)
  if xmlSecCryptoAppInit(cstring_or_null(name)) != 0:
    raise Error("xmlsec crypto app initialization failed")

def cryptoInit():
  """initialize the crypto subsystem.

  `cryptoAppInit` should already have been called.

  Usually, you would use `initialize` rather than this low level function.
  """
  if xmlSecCryptoInit() != 0:
    raise Error("xmlsec crypto initialization failed")

def initialize(name=None):
  """initialize for use of crypto engine *name* (or the default enginw).

  This call combines `init`, `cryptoAppInit` and `cryptoInit`.

  In addition, it reconfigures the error report handling of `xmlsec`
  to use this modules error handler.
  """
  init()
  cryptoAppInit(name)
  cryptoInit()
  xmlSecErrorsSetCallback(<void *> _error_callback)

def addIDs(_Element node, ids):
  """register *ids* as ids used below *node*.

  *ids* is a sequence of attribute names used as XML ids in the subtree
  rooted at *node*.

  A call to `addIds` may be necessary to make known which attributes
  contain XML ids. This is the case, if a transform references
  an id via `XPointer` or a self document uri and the id
  inkey_data_formation is not available by other means (e.g. an associated
  DTD or XML schema).
  """
  retain = []
  cdef const_xmlChar **lst
  cdef int i, n = len(ids)
  cdef xmlNode *c_node = node._c_node
  cdef xmlDoc *doc = node._doc._c_doc
  lst = <const_xmlChar**> stdlib.malloc(sizeof(xmlChar*) * (n + 1))
  if lst == NULL: raise MemoryError
  try:
    for i in range(n):
      lst[i] = <const_xmlChar*> py2xmlChar(ids[i], retain)
    lst[n] = NULL
    with nogil:
      xmlSecAddIDs(doc, c_node, lst)
  finally: stdlib.free(lst)


cdef class Transform:
  cdef xmlSecTransformId id
  cdef object _name_as_variable

  property name:
    def __get__(self): return xmlChar2py(<xmlChar*>self.id.name)

  property name_as_variable:
    def __get__(self): return self._name_as_variable
    def __set__(self, name): self._name_as_variable = name

  property href:
    def __get__(self): return xmlChar2py(<xmlChar*>self.id.href)

  property usage:
    def __get__(self): return self.id.usage


cdef class Key:
  """an `xmlSec` key."""

  cdef xmlSecKeyPtr key

  def __dealloc__(self):
    if self.key != NULL: xmlSecKeyDestroy(self.key)

  @classmethod
  def load(cls, filename, key_data_format, password=None, key_data_type=None):
    """load PKI key from file."""
    cdef xmlSecKeyPtr key
    cdef bytes b_filename = to_filename_bytes(filename)
    cdef char *c_filename = b_filename
    b_password = bytes_or_none(password)
    cdef char *c_password = cstring_or_null(b_password)
    cdef xmlSecKeyDataFormat c_key_data_format = key_data_format
    cdef xmlSecKeyDataType c_key_data_type
    if key_data_type is None: c_key_data_type = xmlSecKeyDataTypeAny
    else: c_key_data_type = key_data_type
    if not min_version(1, 3, 0) and c_key_data_type != xmlSecKeyDataTypeAny:
      raise ValueError("`key_data_type` supported only for `xmlsec 1.3+`")
    with nogil:
      key = xmlSecCryptoAppKeyLoadEx(c_filename, c_key_data_type, c_key_data_format, c_password, NULL, NULL)
    if key == NULL:
      raise ValueError("failed to load key from file", filename)
    # we would like to use `return cls(key)` but this is unsupported by `cython`
    cdef Key k = cls()
    k.key = key
    return k

  @classmethod
  def loadMemory(cls, data, key_data_format, password=None):
    """load PKI key from memory."""
    cdef xmlSecKeyPtr key
    cdef size_t c_size = len(data)
    cdef const_unsigned_char *c_data = <const_unsigned_char*><char*>data
    b_password = bytes_or_none(password)
    cdef const_char *c_password = <const_char *>cstring_or_null(b_password)
    cdef xmlSecKeyDataFormat c_key_data_format = key_data_format
    with nogil:
      key = xmlSecCryptoAppKeyLoadMemory(c_data, c_size, c_key_data_format, c_password, NULL, NULL)
    if key == NULL:
      raise ValueError("failed to load key from memory")
    # we would like to use `return cls(key)` but this is unsupported by `cython`
    cdef Key k = cls()
    k.key = key
    return k

  @classmethod
  def readBinaryFile(cls, KeyData key_data, filename):
    """load (symmetric) key from file.

    load key of kind *key_data* from *filename*.
    """
    cdef xmlSecKeyPtr key
    cdef b_filename = to_filename_bytes(filename)
    cdef char *c_filename = b_filename
    with nogil:
      key = xmlSecKeyReadBinaryFile(key_data.id, c_filename)
    if key == NULL:
      raise ValueError("failed to read key from `%s`" % filename)
    # we would like to use `return cls(key)` but this is unsupported by `cython`
    cdef Key k = cls()
    k.key = key
    return k

  @classmethod
  def readMemory(cls, KeyData key_data, data):
    """load (symmetric) key from memory.

    load key of kind *key_data* from *data*.
    """
    cdef xmlSecKeyPtr key
    cdef size_t c_size = len(data)
    cdef const_unsigned_char *c_data = <const_unsigned_char*><char*>data
    with nogil:
      key = xmlSecKeyReadMemory(key_data.id, c_data, c_size)
    if key == NULL:
      raise ValueError("failed to read key from memory")
    # we would like to use `return cls(key)` but this is unsupported by `cython`
    cdef Key k = cls()
    k.key = key
    return k

  @classmethod
  def generate(cls, KeyData key_data, unsigned int size , unsigned int key_data_type):
    """Generate key of kind *key_data* with *size* and *key_data_type*."""
    cdef xmlSecKeyPtr key
    with nogil:
      key = xmlSecKeyGenerate(key_data.id, size, key_data_type)
    if key == NULL:
      raise ValueError("failed to generate key")
    # we would like to use `return cls(key)` but this is unsupported by `cython`
    cdef Key k = cls()
    k.key = key
    return k

  def loadCert(self, filename, xmlSecKeyDataFormat key_data_format):
    """load certificate of *key_data_format* from *filename*."""
    cdef int rv
    cdef b_filename = to_filename_bytes(filename)
    cdef char *c_filename = b_filename
    with nogil:
      rv = xmlSecCryptoAppKeyCertLoad(self.key, c_filename, key_data_format)
    if rv < 0:
      raise Error("failed to load certificate", filename, rv)

  cdef xmlSecKeyPtr duplicate(self) except NULL:
    """duplicate this xmlsec key."""

    dkey = xmlSecKeyDuplicate(self.key)
    if dkey == NULL:
      raise Error("failing key duplicate")
    return dkey

  property name:
    def __get__(self):
      return xmlChar2py(<xmlChar *>xmlSecKeyGetName(self.key))
    def __set__(self, name):
      retain = []
      rv = xmlSecKeySetName(self.key, <const_xmlChar*>py2xmlChar(name, retain))
      if rv != 0:
        raise Error("failed to set key name", rv)
      

cdef class KeysMngr:
  cdef xmlSecKeysMngrPtr mngr

  def __cinit__(self):
    cdef xmlSecKeysMngrPtr mngr
    mngr = xmlSecKeysMngrCreate()
    if mngr == NULL:
      raise Error("failed to create keys manager")
    cdef int rv
    rv = xmlSecCryptoAppDefaultKeysMngrInit(mngr)
    if rv < 0:
      raise Error("failed to initialize keys manager", rv)
    self.mngr = mngr

  def __dealloc__(self):
    cdef xmlSecKeysMngrPtr mngr = self.mngr
    if mngr != NULL: xmlSecKeysMngrDestroy(mngr)

  def addKey(self, Key key):
    """add (a copy of) *key*."""
    rv = xmlSecCryptoAppDefaultKeysMngrAdoptKey(
      self.mngr, key.duplicate()
      )
    if rv < 0:
      raise Error("failed to add key", rv)

  def loadCert(self, filename, xmlSecKeyDataFormat key_data_format, xmlSecKeyDataType key_data_type):
    """load certificate from *filename*.

    *key_data_format* specifies the key data format.

    *type* specifies the type and is an or of `KeyDataType*` constants.
    """
    cdef int rv
    cdef bytes b_filename = to_filename_bytes(filename)
    cdef char * c_filename = b_filename
    with nogil:
      rv = xmlSecCryptoAppKeysMngrCertLoad(self.mngr, c_filename, key_data_format, key_data_type)
    if rv < 0:
      raise Error("failed to load certificate", rv, filename)

  def loadCertMemory(self, data, xmlSecKeyDataFormat key_data_format, xmlSecKeyDataType key_data_type):
    """load certificate from *data* (a sequence of bytes).

    *key_data_format* specifies the key_data_format.

    *type* specifies the type and is an or of `KeyDataType*` constants.
    """
    cdef int rv
    cdef int c_size = len(data)
    cdef const_unsigned_char *c_data = <const_unsigned_char *><char *>data
    with nogil:
      rv = xmlSecCryptoAppKeysMngrCertLoadMemory(self.mngr, c_data, c_size, key_data_format, key_data_type)
    if rv < 0:
      raise Error("failed to load certificate from memory", rv)



cdef class DSigCtx:
  """Digital signature context."""

  cdef xmlSecDSigCtxPtr ctx

  def __cinit__(self, KeysMngr mngr=None):
    cdef xmlSecKeysMngrPtr _mngr
    _mngr = mngr.mngr if mngr is not None else NULL
    ctx = xmlSecDSigCtxCreate(_mngr)
    if ctx == NULL:
      raise Error("failed to create digital signature context")
    self.ctx = ctx

  def __dealloc__(self):
    if self.ctx != NULL: xmlSecDSigCtxDestroy(self.ctx)

  property signKey:
    # if we want to support key access, we would need to implement
    #   borrowed keys
    def __set__(self, Key key):
      cdef xmlSecKeyPtr xkey
      ctx = self.ctx
      if ctx.signKey != NULL:
        xmlSecKeyDestroy(ctx.signKey)
      # looks like triggering a `cython` bug
      #xkey = key is not None and key.duplicate() or NULL
      if key is None: xkey = NULL
      else: xkey = key.duplicate()
      ctx.signKey = xkey

  def sign(self, _Element node not None):
    """sign according to signature template at *node*."""
    cdef int rv
    with nogil:
      rv = xmlSecDSigCtxSign(self.ctx, node._c_node)
    if rv != 0:
      raise Error("signing failed with return value", rv)

  def verify(self, _Element node not None):
    """verify signature at *node*."""
    cdef int rv
    with nogil:
      rv = xmlSecDSigCtxVerify(self.ctx, node._c_node)
    if rv != 0:
      raise Error("verifying failed with return value", rv)
    if self.ctx.status != xmlSecDSigStatusSucceeded:
      raise VerificationError("signature verification failed", self.ctx.status)

  def signBinary(self, bytes data not None, Transform algorithm not None):
    """sign binary data *data* with *algorithm* and return the signature.

    You must already have set the context's `signKey` (its value must
    be compatible with *algorithm* and signature creation).
    """
    cdef xmlSecDSigCtxPtr ctx = self.ctx
    ctx.operation = xmlSecTransformOperationSign
    self._binary(ctx, data, algorithm)
    if ctx.transformCtx.status != xmlSecTransformStatusFinished:
      raise Error("signing failed with transform status", ctx.transformCtx.status)
    res = ctx.transformCtx.result
    return <bytes> (<char*>res.data)[:res.size]

  def verifyBinary(self, bytes data not None, Transform algorithm not None, bytes signature not None):
    """Verify *signature* for *data* with *algorithm*.

    You must already have set the context's `signKey` (its value must
    be compatible with *algorithm* and signature verification).
    """
    cdef xmlSecDSigCtxPtr ctx = self.ctx
    cdef int rv
    ctx.operation = xmlSecTransformOperationVerify
    self._binary(ctx, data, algorithm)
    rv = xmlSecTransformVerify(
      ctx.signMethod,
      <const_xmlSecByte *><char *> signature,
      len(signature),
      &ctx.transformCtx
      )
    if rv != 0: raise Error("Verification failed with return value", rv)
    if ctx.signMethod.status != xmlSecTransformStatusOk:
      raise VerificationError("Signature verification failed")

  cdef _binary(self, xmlSecDSigCtxPtr ctx, bytes data, Transform algorithm):
    """common helper used for `sign_binary` and `verify_binary`."""
    cdef int rv
    if not (algorithm.id.usage & xmlSecTransformUsageSignatureMethod):
      raise Error("improper signature algorithm")
    if ctx.signMethod != NULL:
      raise Error("Signature context already used; it is designed for one use only")
    ctx.signMethod = xmlSecTransformCtxCreateAndAppend(
      &ctx.transformCtx,
      algorithm.id
      )
    if ctx.signMethod == NULL:
      raise Error("Could not create signature transform")
    ctx.signMethod.operation = ctx.operation
    if ctx.signKey == NULL:
      raise Error("signKey not yet set")
    xmlSecTransformSetKeyReq(ctx.signMethod, &ctx.keyInfoReadCtx.keyReq)
    rv = xmlSecKeyMatch(ctx.signKey, NULL, &ctx.keyInfoReadCtx.keyReq)
    if rv != 1: raise Error("inappropriate key type")
    rv = xmlSecTransformSetKey(ctx.signMethod, ctx.signKey)
    if rv != 0: raise Error("`xmlSecTransfromSetKey` failed", rv)
    rv = xmlSecTransformCtxBinaryExecute(
      &ctx.transformCtx,
      <const_xmlSecByte *><char *> data,
      len(data)
      )
    if rv != 0: 
      raise Error("transformation failed error value", rv)
    if ctx.transformCtx.status != xmlSecTransformStatusFinished:
      raise Error("transformation failed with status", ctx.transformCtx.status)

  def enableReferenceTransform(self, Transform t):
    """enable use of *t* as reference transform.

    Note: by default, all transforms are enabled. The first call of
    `enableReferenceTransform` will switch to explicitely enabled transforms.
    """
    rv = xmlSecDSigCtxEnableReferenceTransform(self.ctx, t.id)
    if rv < 0:
      raise Error("enableReferenceTransform failed", rv)

  def enableSignatureTransform(self, Transform t):
    """enable use of *t* as signature transform.

    Note: by default, all transforms are enabled. The first call of
    `enableSignatureTransform` will switch to explicitely enabled transforms.
    """
    rv = xmlSecDSigCtxEnableSignatureTransform(self.ctx, t.id)
    if rv < 0:
      raise Error("enableSignatureTransform failed", rv)

  def setEnabledKeyData(self, keydata_list):
    cdef KeyData keydata
    cdef xmlSecPtrListPtr enabled_list = &(self.ctx.keyInfoReadCtx.enabledKeyData)
    xmlSecPtrListEmpty(enabled_list)
    for keydata in keydata_list:
        rv = xmlSecPtrListAdd(enabled_list, <xmlSecPtr> keydata.id)
        if rv < 0:
            raise Error("setEnabledKeyData failed")

  property key_info_flags:
    def __get__(self): return self.ctx.keyInfoReadCtx.flags
    def __set__(self, int flags): self.ctx.keyInfoReadCtx.flags = flags



cdef class EncCtx:
  """Encryption context."""

  cdef xmlSecEncCtxPtr ctx

  def __cinit__(self, KeysMngr mngr=None):
    cdef xmlSecKeysMngrPtr _mngr
    _mngr = mngr.mngr if mngr is not None else NULL
    ctx = xmlSecEncCtxCreate(_mngr)
    if ctx == NULL:
      raise Error("failed to create encryption context")
    self.ctx = ctx

  def __dealloc__(self):
    if self.ctx != NULL: xmlSecEncCtxDestroy(self.ctx)

  property encKey:
    # if we want to support key access, we would need to implement
    #   borrowed keys
    def __set__(self, Key key):
      cdef xmlSecKeyPtr xkey
      cdef xmlSecEncCtxPtr ctx = self.ctx
      if ctx.encKey != NULL:
        xmlSecKeyDestroy(ctx.encKey)
      # looks like triggering a `cython` bug
      #xkey = key is not None and key.duplicate() or NULL
      if key is None: xkey = NULL
      else: xkey = key.duplicate()
      ctx.encKey = xkey


  def encryptBinary(self, _Element tmpl not None, data):
    """encrypt binary *data* according to `EncryptedData` template *tmpl* and return the resulting `EncryptedData` subtree.
    """
    cdef int rv
    cdef size_t c_size = len(data)
    cdef xmlNode *t_node = tmpl._c_node
    cdef const_unsigned_char *c_data = <const_unsigned_char *><char *>data
    with nogil:
      t_node = xmlDocCopyNode(t_node, t_node.doc, 1)
    if t_node == NULL:
      raise Error("Copying the template tree failed")
    with nogil:
      rv = xmlSecEncCtxBinaryEncrypt(self.ctx, t_node, c_data, c_size)
    if rv < 0:
      # delete our `t_node` copy
      with nogil:
        xmlFreeNode(t_node)
      raise Error("failed to encrypt binary", rv)
    return elementFactory(tmpl._doc, t_node)

  def encryptXml(self, _Element tmpl not None, _Element node not None):
    """encrpyt *node* using *tmpl* and return the resulting `EncryptedData` element.

    The `Type` attribute of *tmpl* decides whether *node* itself is
    encrypted (`http://www.w3.org/2001/04/xmlenc#Element`)
    or its content (`http://www.w3.org/2001/04/xmlenc#Content`).
    It must have one of these two
    values (or an exception is raised).

    The operation modifies the tree containing *node* in a way that
    `lxml` references to or into this tree may see a surprising state. You
    should no longer rely on them. Especially, you should use
    `getroottree()` on the result to obtain the encrypted result tree.
    """
    cdef xmlSecEncCtxPtr ctx = self.ctx
    cdef int rv
    cdef xmlNode *t_node = tmpl._c_node  # template xmlNode
    cdef xmlNode *e_node = node._c_node  # xmlNode to be encrypted
    cdef _Document e_doc = node._doc     # _Document to be encrypted
    et = tmpl.get("Type")
    if et not in (TypeEncElement,  TypeEncContent):
      raise Error("unsupported `Type` for `encryptXML` (must be `%s` or `%s`)" % (TypeEncElement, TypeEncContent), et)
    # We copy `t_node` to avoid problems with stale `lxml` references into
    # the template
    with nogil:
      t_node = xmlDocCopyNode(t_node, e_node.doc, 1)
    if t_node == NULL:
      raise Error("Copying the template tree failed")
    ctx.flags = XMLSEC_ENC_RETURN_REPLACED_NODE
    with nogil:
      rv = xmlSecEncCtxXmlEncrypt(ctx, t_node, e_node)
    if rv < 0:
      # delete our `t_node` copy
      with nogil:
        xmlFreeNode(t_node)
      raise Error("failed to encrypt xml", rv)
    # clean up replaced nodes
    attemptDeallocations(&ctx.replacedNodeList, e_doc)
    # `t_node` contains the resulting `EncryptedData` element.
    return elementFactory(e_doc, t_node)


  def encryptUri(self, _Element tmpl not None, uri):
    """encrypt binary data obtained from *uri* according to *tmpl*."""
    cdef int rv
    cdef xmlNode *t_node = tmpl._c_node
    if uri is None: raise ValueError("uri must not be `None`")
    retain = []
    cdef xmlChar *c_uri = py2xmlChar(uri, retain)
    with nogil:
      t_node = xmlDocCopyNode(t_node, t_node.doc, 1)
    if t_node == NULL:
      raise Error("Copying the template tree failed")
    with nogil:
      rv = xmlSecEncCtxUriEncrypt(self.ctx, t_node, c_uri)
    if rv < 0:
      # delete our `t_node` copy
      with nogil:
        xmlFreeNode(t_node)
      raise Error("failed to encrypt uri", rv)
    return elementFactory(tmpl._doc, t_node)


  def decrypt(self, _Element node not None):
    """decrypt *node* (an `EncryptedData` element) and return the result.

    The decryption may result in binary data or an XML subtree.
    In the former case, the binary data is returned. In the latter case,
    the input tree is modified and a reference to the decrypted
    XML subtree is returned.

    If the operation modifies the tree,
    `lxml` references to or into this tree may see a surprising state. You
    should no longer rely on them. Especially, you should use
    `getroottree()` on the result to obtain the decrypted result tree.
    """
    cdef xmlSecEncCtxPtr ctx = self.ctx
    cdef xmlNode *enc_node = node._c_node
    cdef int rv
    cdef bint decrypt_content = node.get("Type") == TypeEncContent 
    # must provide sufficient context to find the decrypted node
    parent = node.getparent()
    if parent is not None: enc_index = parent.index(node)
    # prevent `xmlSecEncCtxDecrypt` to release the encrypted node
    #  this is important as `lxml` helds a reference to it.
    ctx.flags = XMLSEC_ENC_RETURN_REPLACED_NODE
    with nogil:
      rv = xmlSecEncCtxDecrypt(ctx, enc_node)
    if rv < 0:
      raise Error("failed to decrypt", rv)
    cdef xmlSecBufferPtr res
    if not ctx.resultReplaced:
      # binary result
      res = ctx.result
      return <bytes> (<char*>ctx.result.data)[:res.size]
    # XML result
    # clean up replaced nodes
    attemptDeallocations(&ctx.replacedNodeList, node._doc)
    if parent is not None:
      if decrypt_content: return parent
      else: return parent[enc_index]
    # root has been replaced
    cdef xmlNode *c_root = xmlDocGetRootElement(node._doc._c_doc)
    if c_root == NULL:
      raise Error("decryption resulted in a non well formed document")
    return elementFactory(node._doc, c_root)

  property key_info_flags:
    def __get__(self): return self.ctx.keyInfoReadCtx.flags
    def __set__(self, int flags): self.ctx.keyInfoReadCtx.flags = flags


cdef xmlChar * py2xmlChar(object obj, object retain) except? NULL:
  """turn *obj* into an `xmlChar` reference.

  *obj* is expected to be either `None`, an utf-8 encoded 0 terminaded string
  or a unicode.

  *retain* is expected to be a Python list, used to hold python objects that
  need to be retained to keep the returned pointer valid.
  """
  cdef char *rv
  if obj is None: rv = NULL
  elif isinstance(obj, unicode):
    ps = obj.encode("utf8")
    retain.append(ps)
    rv = ps
  elif not isinstance(obj, bytes):
    raise TypeError("xmlChar requires `None`, `bytes` or `unicode`")
  else: rv = obj
  return <xmlChar *> rv

cdef xmlChar2py(xmlChar * xs):
  """convert *xs* into `None`, `str` or `unicode`.
  """
  if xs == NULL: return None
  return pyunicode(xs)
  

cdef inline object bytes_or_none(s):
  if s is None: return
  return s if isinstance(s, bytes) else s.encode(d_enc)

cdef inline char * cstring_or_null(b):
  """*b* is either of tyoe `bytes` or `None`."""
  if b is None: return NULL
  return <char *> b


cdef _mkti(xmlSecTransformId id, name=None):
  cdef Transform o = Transform()
  o.id = id
  o._name_as_variable = name and "Transform" + name
  return o

def transforms_list():
  """the list of known transforms."""
  transforms = [
    _mkti(xmlSecTransformRemoveXmlTagsC14NId, "RemoveXmlTagsC14N"),
    _mkti(xmlSecTransformRsaOaepId, "RsaOaep"),
    _mkti(xmlSecTransformRsaPkcs1Id, "RsaPkcs1"),
    _mkti(xmlSecTransformVisa3DHackId, "Visa3DHack"),
    _mkti(xmlSecTransformXPathId),
    _mkti(xmlSecTransformXPath2Id),
    _mkti(xmlSecTransformXPointerId),
    ]
  cdef xmlSecPtrListPtr t_list = xmlSecTransformIdsGet()
  cdef xmlSecSize size = xmlSecPtrListGetSize(t_list), pos = 0
  while pos < size:
    transforms.append(_mkti(<xmlSecTransformId> xmlSecPtrListGetItem(t_list, pos)))
    pos += 1
  return transforms



cdef class KeyData:
  cdef xmlSecKeyDataId id

  property name:
    def __get__(self): return xmlChar2py(<xmlChar*>self.id.name)

  property href:
    def __get__(self): return xmlChar2py(<xmlChar*>self.id.href)


cdef _mkkdi(xmlSecKeyDataId id):
  cdef KeyData o = KeyData()
  o.id = id
  return o

KeyDataName = _mkkdi(xmlSecKeyDataNameId)
KeyDataValue = _mkkdi(xmlSecKeyDataValueId)
KeyDataRetrievalMethod = _mkkdi(xmlSecKeyDataRetrievalMethodId)
KeyDataEncryptedKey = _mkkdi(xmlSecKeyDataEncryptedKeyId)
KeyDataAes = _mkkdi(xmlSecKeyDataAesId)
KeyDataDes = _mkkdi(xmlSecKeyDataDesId)
KeyDataDsa = _mkkdi(xmlSecKeyDataDsaId)
KeyDataHmac = _mkkdi(xmlSecKeyDataHmacId)
KeyDataRsa = _mkkdi(xmlSecKeyDataRsaId)
KeyDataX509 = _mkkdi(xmlSecKeyDataX509Id)
KeyDataRawX509Cert = _mkkdi(xmlSecKeyDataRawX509CertId)


# constants
DSigNs = "http://www.w3.org/2000/09/xmldsig#"
EncNs = "http://www.w3.org/2001/04/xmlenc#"

TypeEncContent = "http://www.w3.org/2001/04/xmlenc#Content"
TypeEncElement = "http://www.w3.org/2001/04/xmlenc#Element"

KeyDataFormatUnknown = xmlSecKeyDataFormatUnknown
KeyDataFormatBinary = xmlSecKeyDataFormatBinary
KeyDataFormatPem = xmlSecKeyDataFormatPem
KeyDataFormatDer = xmlSecKeyDataFormatDer
KeyDataFormatPkcs8Pem = xmlSecKeyDataFormatPkcs8Pem
KeyDataFormatPkcs8Der = xmlSecKeyDataFormatPkcs8Der
KeyDataFormatPkcs12 = xmlSecKeyDataFormatPkcs12
KeyDataFormatCertPem = xmlSecKeyDataFormatCertPem
KeyDataFormatCertDer = xmlSecKeyDataFormatCertDer

DSigStatusUnknown = xmlSecDSigStatusUnknown
DSigStatusSucceeded = xmlSecDSigStatusSucceeded
DSigStatusInvalid = xmlSecDSigStatusInvalid

KeyDataTypeUnknown = xmlSecKeyDataTypeUnknown
KeyDataTypeNone = xmlSecKeyDataTypeNone
KeyDataTypePublic = xmlSecKeyDataTypePublic
KeyDataTypePrivate = xmlSecKeyDataTypePrivate
KeyDataTypeSymmetric = xmlSecKeyDataTypeSymmetric
KeyDataTypeSession = xmlSecKeyDataTypeSession
KeyDataTypePermanent = xmlSecKeyDataTypePermanent
KeyDataTypeTrusted = xmlSecKeyDataTypeTrusted
KeyDataTypeAny = xmlSecKeyDataTypeAny

TransformUsageUnknown = xmlSecTransformUsageUnknown
TransformUsageDSigTransform = xmlSecTransformUsageDSigTransform
TransformUsageC14NMethod = xmlSecTransformUsageC14NMethod
TransformUsageDigestMethod = xmlSecTransformUsageDigestMethod
TransformUsageSignatureMethod = xmlSecTransformUsageSignatureMethod
TransformUsageEncryptionMethod = xmlSecTransformUsageEncryptionMethod
TransformUsageAny = xmlSecTransformUsageAny

TypeEncContent = "http://www.w3.org/2001/04/xmlenc#Content"
TypeEncElement = "http://www.w3.org/2001/04/xmlenc#Element"

KeySearchLax = 0x00008000


# helpers
from sys import getdefaultencoding, getfilesystemencoding
d_enc = getdefaultencoding()
fs_enc = getfilesystemencoding() or d_enc

cdef to_text(char *ct, default=None):
  t = default if ct == NULL else ct
  if isinstance(t, unicode): return t
  return t.decode(d_enc)

cdef bytes to_filename_bytes(filename):
  return filename.encode(fs_enc) if isinstance(filename, unicode) else filename

cdef attemptDeallocation(xmlNode *n, _Document doc):
  """free *n* if there are no `lxml` references into it.

  If there are such references, *n* is freed by `lxml`
  after all those references have been released.
  """
  # We would like to use `attemptDeallocation` from `lxml`'s "proxy.pxi".
  # Unfortunately, it is not exposed
  # We therefore use a trick: wrap *n* into an `_Element`
  # and release it immediately
  assert n.next == NULL, "right sibling exists"
  assert n.prev == NULL, "left sibling exists"
  assert n.parent == NULL, "parent exists"
  if n._private: return # is referenced itself
  if _isElement(n):
    elementFactory(doc, n) # destruction will free *n* if possible
  else:
    # no parent, no siblings, no children, not directly referenced
    # freeable
    assert n.children == NULL, "unexpected children"
    xmlFreeNode(n)


cdef attemptDeallocations(xmlNode *list[], _Document doc):
  """free the nodes in the (doubly linked) *list* if possible.

  See `attemptDeallocation` for details.
  """
  cdef xmlNode *start = list[0]
  cdef xmlNode *next
  list[0] = NULL
  while start:
    next = start.next
    start.next = start.prev = NULL
    attemptDeallocation(start, doc)
    start = next
