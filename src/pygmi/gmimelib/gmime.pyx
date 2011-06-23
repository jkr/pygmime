from cgmime cimport *

def init(flags=None):
    if not flags: 
        flags = 0
    g_mime_init(flags)

##############################################################################
## UTILS
##############################################################################

def decode_header_date(char *date):
    # Note that while the tz_offset optionally goes into a pointer in
    # gmime, I'm just returning a double here, and applications can
    # decide what they want to do with the offset.
    cdef int tz_offset
    timestamp = g_mime_utils_header_decode_date(date, &tz_offset)
    return (timestamp, tz_offset)

def generate_message_id (char *fqdn):
    return g_mime_utils_generate_message_id(fqdn)

def decode_message_id (char *message_id):
    return g_mime_utils_decode_message_id(message_id)

##############################################################################
## REFERENCES
##############################################################################
cdef class References(object):
    cdef GMimeReferences *_c_gmreferences

    def get_message_id(self):
        return g_mime_references_get_message_id(self._c_gmreferences)

    def get_next(self):
        cdef GMimeReferences *next_gmr = \
            g_mime_references_get_next(self._c_gmreferences)
        return mk_references(next_gmr)

    def append(self, char *msg_id):
        g_mime_references_append(&self._c_gmreferences, msg_id)

    def _is_null(self):
        return self._c_gmreferences == NULL


#static initializer
cdef References mk_references(GMimeReferences *gmr):
    refs = References()
    refs._c_gmreferences = gmr
    return refs

# text to References
def decode_references(char *text):
    cdef GMimeReferences *gmr = g_mime_references_decode(text)
    return mk_references(gmr)

##############################################################################
## STREAM
##############################################################################

cdef class Stream (object):
    cdef GMimeStream *_c_gmstream

    cdef _from_gmime_stream(self, GMimeStream* _c_gmstream):
        self._c_gmstream = _c_gmstream

    def from_file(self, char* filename):
        cdef FILE* fp = fopen(filename, "rb")
        cdef GMimeStream *gms = g_mime_stream_file_new(fp)
        self._from_gmime_stream(gms)

    def from_stdin(self):
        cdef GMimeStream *gms = g_mime_stream_file_new(stdin)
        self._from_gmime_stream(gms)

    def from_bytes(self, bytes data):
        cdef GByteArray *garray = g_byte_array_new()
        g_byte_array_append(garray, data, len(data))
        cdef GMimeStream *gms = g_mime_stream_mem_new_with_byte_array(garray)
        self._from_gmime_stream(gms)

    def make_parser(self):
        cdef GMimeParser *gmp = g_mime_parser_new_with_stream(self._c_gmstream)
        return mk_parser(gmp)

    def make_data_wrapper(self, GMimeContentEncoding encoding):
        cdef GMimeDataWrapper *gmdw = \
             g_mime_data_wrapper_new_with_stream(self._c_gmstream, encoding)
        return mk_data_wrapper(gmdw)

    def reset(self):
        g_mime_stream_reset(self._c_gmstream)

    def size(self):
        return g_mime_stream_length(self._c_gmstream)

    def tell(self):
        return g_mime_stream_tell(self._c_gmstream)

    def flush(self):
        g_mime_stream_flush(self._c_gmstream)

    def close(self):
        out = g_mime_stream_close(self._c_gmstream)
        if not out == 0:
            raise Exception, "Couldn't close the stream."

##############################################################################
## PARSER
##############################################################################

cdef class Parser (object):
    cdef GMimeParser *_c_gmparser

    def construct_part(self):
        return mk_mime_object(g_mime_parser_construct_part(self._c_gmparser))

    def construct_message(self):
        cdef GMimeMessage *msg = \
             g_mime_parser_construct_message(self._c_gmparser)
        return mk_message(msg)

# Initializer from a GMimeStream
cdef Parser mk_parser (GMimeParser *gmp):
    p = Parser()
    p._c_gmparser = gmp
    return p

##############################################################################
## DATA WRAPPER
##############################################################################

cdef class DataWrapper (object):

    cdef GMimeDataWrapper *_c_gmdatawrapper

    def get_data(self):
        cdef GByteArray *garray = g_byte_array_new()
        cdef GMimeStream *outstream = \
             g_mime_stream_mem_new_with_byte_array(garray)
        g_mime_data_wrapper_write_to_stream (self._c_gmdatawrapper, outstream)
        # We have to call an explicit slice to get the length, because
        # strlen() will fail with bytearrays that have \x00 in them.
        return garray.data[:g_mime_stream_length(outstream)]


# Initializer from a GMimeDataWrapper
cdef DataWrapper mk_data_wrapper (GMimeDataWrapper *gmdw):
    dw = DataWrapper()
    dw._c_gmdatawrapper = gmdw
    return dw

##############################################################################
## CIPHER CONTEXT
##############################################################################

cdef class CipherContext(object):

    cdef GMimeCipherContext *_c_gmciphercontext

    def is_gpg_context(self):
        return GMIME_IS_GPG_CONTEXT(self._c_gmciphercontext)

    def to_gpg_context(self):
        return mk_gpg_context (GMIME_GPG_CONTEXT(self._c_gmciphercontext))

# Initializer from a GMimeCipherContext
cdef CipherContext mk_cipher_context (GMimeCipherContext *gmctx):
    ctx = CipherContext()
    ctx._c_gmciphercontext = gmctx
    return ctx

##############################################################################
## GPG CIPHER CONTEXT
##############################################################################

cdef class GPGContext(CipherContext):

    cdef GMimeGpgContext *_c_gmgpgcontext

    def set_always_trust(self, bint always_trust):
        g_mime_gpg_context_set_always_trust(self._c_gmgpgcontext,
                                            always_trust)

# Initializer from a GMimeGpgContext
cdef GPGContext mk_gpg_context (GMimeGpgContext *gmgpg):
    ctx = GPGContext()
    ctx._c_gmgpgcontext = gmgpg
    ctx._c_gmciphercontext = GMIME_CIPHER_CONTEXT(gmgpg)
    return ctx

##############################################################################
## GMIME SESSION
##############################################################################

cdef class Session(object):

    cdef GMimeSession *_c_gmsession

    def __cinit__(self):
        self._c_gmsession = GMIME_SESSION (
            g_object_new( g_mime_session_get_type(), NULL)
            )

    def request_password(self, char* prompt, bint secret, char *item):
        cdef GError *err = NULL
        cdef char *passwd = \
             g_mime_session_request_passwd(self._c_gmsession,
                                           prompt,
                                           secret,
                                           item,
                                           &err)
        if err != NULL:
            raise Exception, "Error requesting password: " + err.message
        else:
            return passwd

    def forget_password(self, char *item):
        cdef GError *err = NULL
        g_mime_session_forget_passwd(self._c_gmsession,
                                     item,
                                     &err)
        if err != NULL:
            raise Exception, "Error forgetting password: " + err.message

    def is_online(self):
        return g_mime_session_is_online (self._c_gmsession)

    def new_gpg_context(self, char *path):
        cdef GMimeCipherContext *ctx = \
             g_mime_gpg_context_new(self._c_gmsession, path)
        return mk_cipher_context(ctx)

##############################################################################
## GMIME SESSION SIMPLE (SESSION)
##############################################################################

cdef class SessionSimple(Session):

    cdef GMimeSessionSimple *_c_gmsessionsimple

    def __cinit__(self):
        super(SessionSimple, self).__init__()


##############################################################################
## MIME OBJECT
##############################################################################

cdef class MimeObject (object):

    """Note: To try to deal correctly with the way that GMime
    implements its object hierarchy, every method that is inherited by
    MimeObject's subclasses does a cast first."""

    # TODO: See if we can change the cast to a decorator.

    cdef GMimeObject *_c_gmobject

    def get_headers(self):
        cdef GMimeHeaderList *gmhl = \
             g_mime_object_get_header_list(self._c_gmobject)
        return mk_header_list(gmhl)

    def to_string(self): 
        return g_mime_object_to_string (self._c_gmobject)

    def make_stream(self):
        cdef GMimeStream *gmstrm = g_mime_stream_mem_new ()
        g_mime_object_write_to_stream(self._c_gmobject, gmstrm)
        stream = Stream()
        stream._from_gmime_stream(gmstrm)
        stream.reset()
        return stream

    def is_part(self):
        return GMIME_IS_PART (self._c_gmobject)

    def to_part(self):
        if not self.is_part():
            raise Exception, "Can't convert to part"

        cdef GMimePart *gmp = GMIME_PART (self._c_gmobject)
        return mk_part(gmp)
 
    def is_multipart(self):
        return GMIME_IS_MULTIPART (self._c_gmobject)

    def to_multipart(self):
        if not self.is_multipart():
            raise Exception, "Can't convert to multipart"

        cdef GMimeMultipart *gmmp = GMIME_MULTIPART (self._c_gmobject)
        return mk_multipart(gmmp)

    def is_message(self):
        return GMIME_IS_MESSAGE (self._c_gmobject)

    def to_message(self):
        if not self.is_message():
            raise Exception, "Can't convert to message"
        cdef GMimeMessage *gmsg = GMIME_MESSAGE(self._c_gmobject)
        return mk_message(gmsg)

    def is_message_part(self):
        return GMIME_IS_MESSAGE_PART (self._c_gmobject)

    def to_message_part(self):
        if not self.is_message_part():
            raise Exception, "Can't convert to message"
        cdef GMimeMessagePart *gmsgprt = GMIME_MESSAGE_PART(self._c_gmobject)
        return mk_message_part(gmsgprt)

# Static initalizer
cdef MimeObject mk_mime_object(GMimeObject *obj):
    mo = MimeObject()
    mo._c_gmobject = obj
    return mo

##############################################################################
## PART (MIME OBJECT)
##############################################################################

cdef class Part (MimeObject):

    cdef GMimePart *_c_gmpart

    def __cinit__(self):
        MimeObject.__init__(self)

    def get_content_object(self):
        cdef GMimeObject *gmobj = self._c_gmobject
        cdef GMimeDataWrapper *gmdw = \
             g_mime_part_get_content_object (GMIME_PART(gmobj))
        return mk_data_wrapper(gmdw)
        
    def get_content_description (self):
        out = g_mime_part_get_content_description (self._c_gmpart)
        if out:
            return out
        else:
            return None

    def get_content_id (self):
        out = g_mime_part_get_content_id (self._c_gmpart)
        if out:
            return out
        else:
            return None

    def get_content_md5 (self):
        out = g_mime_part_get_content_md5 (self._c_gmpart)
        if out:
            return out
        else:
            return None

    def verify_content_md5 (self):
        out = g_mime_part_verify_content_md5 (self._c_gmpart)
        if out:
            return out
        else:
            return None

    def get_content_location (self):
        out = g_mime_part_get_content_location (self._c_gmpart)
        if out:
            return out
        else:
            return None

    def get_content_encoding (self):
        out = g_mime_part_get_content_encoding (self._c_gmpart)
        if out:
            return out
        else:
            return None

    def get_filename (self):
        out = g_mime_part_get_filename (self._c_gmpart)
        if out:
            return out
        else:
            return None

# Static initalizer
cdef Part mk_part(GMimePart *gmp):
    p = Part()
    p._c_gmpart = gmp
    p._c_gmobject = GMIME_OBJECT(gmp)
    return p

##############################################################################
## MULTIPART (MIME OBJECT)
##############################################################################

cdef class Multipart (MimeObject):

    cdef GMimeMultipart *_c_gmmultipart

    def __cinit__(self):
        MimeObject.__init__(self)

    def get_count(self):
        return g_mime_multipart_get_count (self._c_gmmultipart)

    def get_part(self, int partidx):
        cdef GMimeObject *obj = g_mime_multipart_get_part (self._c_gmmultipart,
                                                           partidx)
        return mk_mime_object(obj)

    def get_subpart_from_content_id (self, char *content_id):
        cdef GMimeObject *obj = \
             g_mime_multipart_get_subpart_from_content_id (self._c_gmmultipart,
                                                           content_id)

        return mk_mime_object(obj)

    def is_multipart_encrypted(self):
        return GMIME_IS_MULTIPART_ENCRYPTED (self._c_gmobject)

    def to_multipart_encrypted(self):
        if not self.is_multipart():
            raise Exception, "Can't convert to multipart encrypted"

        cdef GMimeMultipartEncrypted *gmme = GMIME_MULTIPART_ENCRYPTED (self._c_gmobject)
        return mk_multipart_encrypted(gmme)

    def is_multipart_signed(self):
        return GMIME_IS_MULTIPART_SIGNED (self._c_gmobject)

    def to_multipart_signed(self):
        if not self.is_multipart():
            raise Exception, "Can't convert to multipart encrypted"

        cdef GMimeMultipartSigned *gmms = GMIME_MULTIPART_SIGNED (self._c_gmobject)
        return mk_multipart_signed(gmms)


# Static initalizer
cdef Multipart mk_multipart(GMimeMultipart *gmmp):
    mp = Multipart()
    mp._c_gmmultipart = gmmp
    mp._c_gmobject = GMIME_OBJECT(gmmp)
    return mp

##############################################################################
## MULTIPART ENCRYPTED (MULTIPART)
##############################################################################

cdef class MultipartEncrypted(Multipart):

    cdef GMimeMultipartEncrypted *_c_gmmultipartencrypted

    def __cinit__(self):
        Multipart.__init__(self)

    def decrypt(self, CipherContext ctx):
        cdef GError *err = NULL
        cdef GMimeObject *obj = \
            g_mime_multipart_encrypted_decrypt(self._c_gmmultipartencrypted,
                                               ctx._c_gmciphercontext,
                                               &err)
        if err != NULL:
            raise Exception, "decryption failed: " + err.message
        else:
            return mk_mime_object(obj)

# Static initializer
cdef MultipartEncrypted mk_multipart_encrypted(GMimeMultipartEncrypted *gmpe):
    mpe = MultipartEncrypted()
    mpe._c_gmmultipartencrypted = gmpe
    mpe._c_gmobject = GMIME_OBJECT(gmpe)
    mpe._c_gmmultipart = GMIME_MULTIPART(mpe._c_gmobject)
    return mpe

##############################################################################
## MULTIPART SIGNED (MULTIPART)
##############################################################################

cdef class MultipartSigned(Multipart):

    cdef GMimeMultipartSigned *_c_gmmultipartsigned

    def __cinit__(self):
        Multipart.__init__(self)

    # def verify(self, CipherContext ctx):
    #     cdef GError *err = NULL
    #     cdef GMimeSignatureValidity *sigval = \
    #         g_mime_multipart_signed_verify(self._c_gmmultipartsigned,
    #                                        ctx._c_gmciphercontext,
    #                                        &err)
    #     if err != NULL:
    #         raise Exception, "Verification failed: " + err.message
    #     else:
    #         return mk_signature_validity(sigval)

# Static initializer
cdef MultipartEncrypted mk_multipart_signed(GMimeMultipartSigned *gmps):
    mps = MultipartSigned()
    mps._c_gmmultipartsigned = gmps
    mps._c_gmobject = GMIME_OBJECT(gmps)
    mps._c_gmmultipart = GMIME_MULTIPART(mps._c_gmobject)
    return mps

##############################################################################
## MESSAGE (MIME OBJECT)
##############################################################################

cdef class Message (MimeObject):

    cdef GMimeMessage *_c_gmmessage

    def __cinit__(self):
        MimeObject.__init__(self)

    def get_sender(self):
        return g_mime_message_get_sender(self._c_gmmessage)

    def get_reply_to(self):
        return g_mime_message_get_reply_to(self._c_gmmessage)

    def get_subject(self):
        return g_mime_message_get_subject(self._c_gmmessage) 

    def get_date_as_string(self):
        return g_mime_message_get_date_as_string(self._c_gmmessage) 

    def get_message_id(self):
        return g_mime_message_get_message_id(self._c_gmmessage)

    def get_mime_part(self):
        cdef GMimeObject *obj = g_mime_message_get_mime_part(self._c_gmmessage)
        return mk_mime_object(obj)

# Static initalizer
cdef Message mk_message(GMimeMessage *gmmsg):
    msg = Message()
    msg._c_gmmessage = gmmsg
    msg._c_gmobject = GMIME_OBJECT(gmmsg)
    return msg

##############################################################################
## MESSAGE PART (MIME OBJECT)
##############################################################################

cdef class MessagePart(MimeObject):

    cdef GMimeMessagePart *_c_gmmessagepart

    def __cinit__(self):
        MimeObject.__init__(self)

    def get_message(self):
        cdef GMimeMessage *gmmsg = \
             g_mime_message_part_get_message(self._c_gmmessagepart)
        return mk_message(gmmsg)

# Static initalizer
cdef MessagePart mk_message_part(GMimeMessagePart *gmmp):
    msgpart = MessagePart()
    msgpart._c_gmmessagepart = gmmp
    msgpart._c_gmobject = GMIME_OBJECT(gmmp)
    return msgpart

##############################################################################
## HEADERS
##############################################################################

cdef class Headers(object):
    cdef GMimeHeaderList *_c_gmheaderlist
    cdef GMimeHeaderIter *_header_iter
    cdef bint _iter_done

    def __cinit__(self):
        self._iter_done = False

    def iter_get_name(self):
        return g_mime_header_iter_get_name (self._header_iter)

    def iter_get_value(self):
        return g_mime_header_iter_get_value (self._header_iter)

    def iter_first (self):
        return g_mime_header_iter_first (self._header_iter)

    def iter_last (self):
        return g_mime_header_iter_last (self._header_iter)

    def iter_next (self):
        return g_mime_header_iter_next (self._header_iter)

    def iter_prev (self):
        return g_mime_header_iter_prev (self._header_iter)

    def iter_is_valid (self):
        return g_mime_header_iter_is_valid (self._header_iter)

    def get(self, char *name):
        value = g_mime_header_list_get(self._c_gmheaderlist, name)
        if value == NULL:
            raise KeyError, name
        else:
            return value

# Initializer from GMimeHeaderList
cdef Headers mk_header_list(GMimeHeaderList *gmhdrs):
    h = Headers()
    h._c_gmheaderlist = gmhdrs
    h._header_iter = g_mime_header_iter_new()
    g_mime_header_list_get_iter(h._c_gmheaderlist, h._header_iter)
    return h

##############################################################################
## CONTENT-TYPE 
##############################################################################

cdef class ContentType(object):
    cdef GMimeContentType *_c_gmcontenttype
    
    # cdef _from_gmime_content_type(self, GMimeContentType *gmct):
    #     self._c_gmcontenttype = gmct

    # def new_from_string(self,s):
    #     self._from_gmime_content_type(g_mime_content_type_new_from_string (s))

    def to_string(self):
        return g_mime_content_type_to_string (self._c_gmcontenttype)

    def get_media_type (self):
        return g_mime_content_type_get_media_type (self._c_gmcontenttype)

    def get_media_subtype (self):
        return g_mime_content_type_get_media_subtype (self._c_gmcontenttype)

    def get_params (self):
        cdef GMimeParam* gmp = g_mime_content_type_get_params (self._c_gmcontenttype)
        return mk_parameters(gmp)

    def get_parameter (self, char *attribute):
        return g_mime_content_type_get_parameter (self._c_gmcontenttype, attribute)


# Static construction function
def string_to_content_type(char *string):
    """A static function that takes a string and returns a
    ContentType() class."""
    cdef ContentType ct = ContentType()
    ct._c_gmcontenttype = g_mime_content_type_new_from_string (string)
    return ct


##############################################################################
## PARAMETERS
##############################################################################

cdef class Param(object):
    cdef GMimeParam *_c_gmparameters
    
    def _is_null(self):
        return (self._c_gmparameters == NULL)
    
    def next(self):
        return mk_parameters(g_mime_param_next (self._c_gmparameters))
                                                               
    def get_name(self):                                        
        if self._is_null():                                    
            return None                                        
        else:                                                  
            return g_mime_param_get_name(self._c_gmparameters) 
                                                               
    def get_value(self):                                       
        if self._is_null():                                    
            return None
        else:
            return g_mime_param_get_value(self._c_gmparameters)

    cdef _from_gmime_parameters(self, GMimeParam *gmp):
        self._c_gmparameters = gmp

# Static initalizer
cdef Param mk_parameters(GMimeParam *gmp):
    param = Param()
    param._c_gmparameters = gmp
    return param

##############################################################################
## CONTENT-DISPOSITION
##############################################################################

cdef class ContentDisposition(object):
    cdef GMimeContentDisposition *_c_gmcontentdisposition
    
    cdef _from_gmime_content_disposition(self, GMimeContentDisposition *gmd):
        self._c_gmcontentdisposition = gmd

    def new_from_string(self,s):
        self._from_gmime_content_disposition(g_mime_content_disposition_new_from_string (s))

    def get_disposition(self):
        return g_mime_content_disposition_get_disposition (self._c_gmcontentdisposition)

    def get_params(self):
        cdef GMimeParam *gmp = g_mime_content_disposition_get_params (self._c_gmcontentdisposition)
        param = Param()
        param._from_gmime_parameters(gmp)
        return param

    def get_parameter(self, char *attribute):
        return g_mime_content_disposition_get_parameter (self._c_gmcontentdisposition, attribute)

    def to_string(self, bint fold = True):
        return g_mime_content_disposition_to_string (self._c_gmcontentdisposition, fold)

# Static construction function
def string_to_content_disposition(char *string):
    """A static function that takes a string and returns a
    ContentDisposition() class."""
    cdef ContentDisposition cd = ContentDisposition()
    cd.new_from_string(string)
    return cd

##############################################################################
## INTERNET ADDRESS
##############################################################################

cdef class InternetAddress(object):
    cdef CInternetAddress *_c_internet_address
    
    def get_name(self):
        out = internet_address_get_name(self._c_internet_address)
        if out is NULL:
            return None
        else:
            return out

    def set_name(self, char *name):
        internet_address_set_name(self._c_internet_address, name)

    def to_string(self, bint encode=True):
        return internet_address_to_string(self._c_internet_address, encode)

    def is_internet_address_mailbox(self):
        return INTERNET_ADDRESS_IS_MAILBOX(self._c_internet_address)

    def to_internet_address_mailbox(self):
        if not self.is_internet_address_mailbox():
            raise Exception, "Can't convert to message"
        cdef CInternetAddressMailbox *iam = INTERNET_ADDRESS_MAILBOX(self._c_internet_address)
        return mk_internet_address_mailbox(iam)

    def is_internet_address_group(self):
        return INTERNET_ADDRESS_IS_GROUP(self._c_internet_address)

    def to_internet_address_group(self):
        if not self.is_internet_address_group():
            raise Exception, "Can't convert to message"
        cdef CInternetAddressGroup *iag = INTERNET_ADDRESS_GROUP(self._c_internet_address)
        return mk_internet_address_group(iag)

    def to_internet_address(self):
        return <InternetAddress>self

cdef InternetAddress mk_internet_address(CInternetAddress *cia):
     ia = InternetAddress()
     ia._c_internet_address = cia
     return ia

##############################################################################
## INTERNET ADDRESS LIST
##############################################################################

class InternetAddressListError(Exception):
    pass

cdef class InternetAddressList(object):

    cdef CInternetAddressList *_c_internet_address_list

    def __cinit__(self):
        self._c_internet_address_list = internet_address_list_new()
    
    def length(self):
        return internet_address_list_length(self._c_internet_address_list)

    def contains(self, InternetAddress ia):
        return internet_address_list_contains(self._c_internet_address_list,
                                              ia._c_internet_address)

    def index_of(self, InternetAddress ia):
        return internet_address_list_index_of(self._c_internet_address_list,
                                              ia._c_internet_address)

    def get_address(self, int idx):
        cdef CInternetAddress *cia = internet_address_list_get_address (
            self._c_internet_address_list,
            idx)
        return mk_internet_address(cia)

    def to_string(self, bint encode=True):
        out_str = internet_address_list_to_string(self._c_internet_address_list, encode)
        if out_str == NULL:
            return ""
        else:
            return out_str

    def append(self, InternetAddressList other):
        internet_address_list_append(self._c_internet_address_list,
                                     other._c_internet_address_list)

    def add(self, InternetAddress addr):
        idx = internet_address_list_add (self._c_internet_address_list,
                                         addr._c_internet_address)
        return idx

    def insert(self, InternetAddress addr, int idx):
        internet_address_list_insert (self._c_internet_address_list,
                                      idx,
                                      addr._c_internet_address)

    def remove(self, InternetAddress addr):
        out_bool = internet_address_list_remove (self._c_internet_address_list,
                                                 addr._c_internet_address)
        if not out_bool:
            raise InternetAddressListError, "Couldn't remove item %s" % addr

    def remove_at(self, int idx):
        out_bool = internet_address_list_remove_at (self._c_internet_address_list,
                                                    idx)
        if not out_bool:
            raise InternetAddressListError, "Couldn't remove item at index %d" % idx


cdef InternetAddressList mk_internet_address_list(CInternetAddressList *cial):
    cdef InternetAddressList ial = InternetAddressList()
    ial._c_internet_address_list = cial
    return ial


# Static construction function
def parse_internet_address_list(char *s):
    """A static function that takes a string and returns an
    InternetAddressList() object."""
    cdef CInternetAddressList *cial = internet_address_list_parse_string (s)
    return mk_internet_address_list(cial)

##############################################################################
## INTERNET ADDRESS MAILBOX (STANDARD ADDRESS)
##############################################################################

cdef class InternetAddressMailbox(InternetAddress):

    cdef CInternetAddressMailbox *_c_internet_address_mailbox

    def __cinit__(self, char *name, char *addr):
        self._c_internet_address = internet_address_mailbox_new(name, addr)
        self._c_internet_address_mailbox = INTERNET_ADDRESS_MAILBOX (self._c_internet_address)

    def get_addr(self):
        return internet_address_mailbox_get_addr(self._c_internet_address_mailbox)

    def set_addr(self, char *addr):
        internet_address_mailbox_set_addr(self._c_internet_address_mailbox, addr)
        

cdef InternetAddressMailbox mk_internet_address_mailbox(CInternetAddressMailbox *iam):
    mailbox = InternetAddressMailbox(None, None)
    mailbox._c_internet_address_mailbox = iam
    mailbox._c_internet_address = INTERNET_ADDRESS(iam)
    return mailbox

##############################################################################
## INTERNET ADDRESS GROUP 
##############################################################################

cdef class InternetAddressGroup(InternetAddress):

    cdef CInternetAddressGroup *_c_internet_address_group

    def __cinit__(self, char *name):
        self._c_internet_address = internet_address_group_new(name)
        self._c_internet_address_group = INTERNET_ADDRESS_GROUP (self._c_internet_address)

    def get_members(self):
        cdef CInternetAddressList *cial 
        cial = internet_address_group_get_members(self._c_internet_address_group)
        return mk_internet_address_list(cial)

    def set_members(self, InternetAddressList members):
        internet_address_group_set_members (self._c_internet_address_group,
                                            members._c_internet_address_list)

    def add_member(self, InternetAddress member):
        idx = internet_address_group_add_member (self._c_internet_address_group,
                                                  member._c_internet_address)
        return idx

cdef InternetAddressGroup mk_internet_address_group(CInternetAddressGroup *iag):
    group = InternetAddressGroup(None)
    group._c_internet_address_group = iag
    group._c_internet_address = INTERNET_ADDRESS(iag)
    return group



        

        

