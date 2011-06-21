import gmimelib
try:
    import GnuPGInterface
    GPG_ENABLED = True
except ImportError:
    GPG_ENABLED = False


class PygmiError(Exception):
    pass

class ParserError(Exception):
    pass

class AddressListIndexError(Exception):
    pass

class HeaderNameError(Exception):
    pass

class MimeObjectTypeError(Exception):
    pass

class MultipartError(Exception):
    pass

class Address(object):

    def __init__(self):
        self._gmaddress = None
        self.display_name = None

    def __str__(self):
        return self.gmaddress.to_string()

    @staticmethod
    def _from_gmime_address(gmaddress):
        a = Address()
        a.gmaddress = gmaddress
        a.display_name = gmaddress.get_name()
        return a

    @staticmethod
    def from_string(address_str):
        return AddressList(address_str)[0]

class AddressList(object):

    def __init__(self, address_list):
        self.address_list = gmimelib.parse_internet_address_list(address_list)

    def __getitem__(self, idx):
        if idx < len(self):
            gmaddress = self.address_list.get_address(idx)
            return Address._from_gmime_address(gmaddress)
        else:
            raise AddressListIndexError, idx

    def __len__(self):
        return self.address_list.length()

    def __iter__(self):
        def address_generator(add_lst):
            for i in xrange(len(add_lst)):
                yield add_lst[i]
        return address_generator(self)

    def __str__(self):
        return self.address_list.to_string()

class References(object):
    
    def __init__(self, references_str):
        if references_str is None:
            references_str = ""
        self.refs = gmimelib.decode_references(references_str)
        self._full_refs = gmimelib.decode_references(references_str)
        
    def __iter__(self):
        return self

    def next(self):
        if self.refs._is_null():
            self.refs = self._full_refs
            raise StopIteration
        else:
            msgid = self.refs.get_message_id()
            self.refs = self.refs.get_next()
            return msgid

    def __len__(self):
        return len(list(self))

class Header(object):

    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __repr__(self):
        return "Header(%s: %s)" % (self.name, self.value)

class Headers(object):

    def __init__(self, gmime_headers):
        self._headers = gmime_headers
        self._iter_done = False

    def get(self, name):
        try:
            return self._headers.get(name)
        except KeyError:
            return None

    def __iter__(self):
        return self

    def next(self):
        if self._iter_done:
            self._headers.iter_first()
            self._iter_done = False
            raise StopIteration
        out = Header(self._headers.iter_get_name(), self._headers.iter_get_value())
        if not self._headers.iter_next():
            self._iter_done = True
        return out

class Parser(object):

    def __init__(self):
        self.stream = None
        self.stream_parser = None

    def _from_stream(self, stream):
        self.stream = stream

    def read_file(self, filename):
        self.stream = gmimelib.Stream()
        self.stream.from_file(filename)

    def read_string(self, bts):
        self.stream = gmimelib.Stream()
        self.stream.from_bytes(bts)

    def parse(self):
        if self.stream is None:
            raise ParserError, "Nothing to parse"
        else:
            parser = self.stream.make_parser()
            msg = parser.construct_message()
            return Message(mime_object = msg)

    def _reset(self):
        self.stream.reset()

    def close(self):
        self.stream.close()


class MimeObject(object):

    # def __init__(self, mime_object, parent=None):
    #     self.mime_object = mime_object
    #     self.parent = parent
    #     if self.mime_object.is_message():
    #         self._part = None
    #     else:
    #         self._part = mime_object

    @staticmethod
    def _mk_mime_object(obj, parent):
        if obj.is_message():
            return Message(obj, parent)
        elif obj.is_part():
            return Part(obj, parent)
        elif obj.is_message_part():
            return MessagePart(obj, parent)
        elif obj.is_multipart():
            if obj.to_multipart().is_multipart_encrypted():
                return Encrypted(obj, parent)
            elif obj.to_multipart().is_multipart_signed():
                return Signed(obj, parent)
            else:
                return Multipart(obj, parent)
        else:
            raise MimeObjectTypeError ("%s is not an acceptable mimeobject type" % obj)

    def __init__(self):
        self._part = None


    # We don't want to parse out the mime part unless we need it. So
    # we make a decorator that will make the _part attribute if
    # needed.
    def _requires_part(fun):
        def internal_fun (self, *args):
            if not self._part:
                self._part = self.mime_object.get_mime_part()
            return fun(self, *args)
        return internal_fun

    def get_headers(self):
        return Headers(self.mime_object.get_headers())

    def get_content_type(self):
        try:
            h = self.get_headers()
            ct_str = h.get('content-type')
            ct = gmimelib.string_to_content_type(ct_str)
            return (ct.get_media_type(), ct.get_media_subtype())
        except HeaderNameError:
            return None

    def get_parameters(self):
        try:
            h = self.get_headers()
            ct_str = h.get('content-type')
            ct = gmimelib.string_to_content_type(ct_str)
            def paramgen(content_type):
                param = content_type.get_params()
                while not param._is_null():
                    yield (param.get_name(), param.get_value())
                    param = param.next()
            return paramgen(ct)
        except HeaderNameError:
            return None

    def get_content_description (self):
        return None

    def get_content_id (self):
        return None

    def get_content_md5 (self):
        return None

    def verify_content_md5 (self):
        raise MimeObjectTypeError

    def get_content_location (self):
        return None

    def get_content_encoding (self):
        return None

    def get_filename (self):
        return None

    def is_message(self):
        return None

    def is_part(self):
        return False
        return self.mime_object.is_part()

    def is_message_part(self):
        return False

    def is_multipart(self):
        return False

    def get_child_count(self):
        return None

    def get_child(self, idx):
        raise MultipartError

    def has_children(self):
        return False

    def children (self):
        raise MultipartError, "No children"

    def __iter__(self):
        return self.children()

    def get_data(self):
        return None

    def to_string(self):
        return self.mime_object.to_string()

    def walk(self):
        if not self.has_children():
            yield self
        else:
            for child in self:
                for grandchild in child.walk():
                    yield grandchild
                

class Message(MimeObject):

    def __init__(self, mime_object, parent=None):
        self.mime_object = mime_object
        self.parent = parent
        #super(Message, self).__init__(msg, parent)

    def is_message(self):
        return True

    def get_child_count(self):
        return 1

    def has_children(self):
        return True

    def get_child(self, idx):
        if idx > 0:
            return MultipartError, idx
        else:
            prt = self.mime_object.get_mime_part()
            return MimeObject._mk_mime_object(prt, self)

    def children(self):
        yield self.get_child(0)

class MessagePart(MimeObject):

    def __init__(self, mime_object, parent=None):
        self.mime_object = mime_object
        self.parent = parent
        #super(MessagePart, self).__init__(msgpart, parent)

    def is_message_part(self):
        return True

    def get_child_count(self):
        return 1

    def has_children(self):
        return True

    def get_child(self):
        if idx > 0:
            return MultipartError, idx
        else:
            msg = self.mime_object.to_message_part().get_message()
            return MimeObject._mk_mime_object(msg, self)

    def children(self):
        yield self.get_child(0)

class Part(MimeObject):

    def __init__(self, mime_object, parent=None):
        self.message_object = None
        self.mime_object = mime_object
        self.parent = parent
        #super(Part, self).__init__(part, parent)

    def is_part(self):
        return True

    def get_content_description (self):
        return self.mime_object.to_part().get_content_description()

    def get_content_id (self):
        return self.mime_object.to_part().get_content_id ()

    def get_content_md5 (self):
        return self.mime_object.to_part().get_content_md5 ()

    def verify_content_md5 (self):
        return self.mime_object.to_part().verify_content_md5 ()

    def get_content_location (self):
        self.mime_object.to_part().get_content_location ()

    def get_content_encoding (self):
        return self.mime_object.to_part().get_content_encoding ()

    def get_filename (self):
        return self.mime_object.to_part().get_filename ()

    def get_data(self):
        datawrapper = self.mime_object.to_part().get_content_object()
        return datawrapper.get_data()

class Multipart(MimeObject):

    def __init__(self, mime_object, parent=None):
        self.message_object = None
        self.mime_object = mime_object
        self.parent = parent
        #super(Multipart, self).__init__(multipart, parent)

    def is_multipart(self):
        return True

    def is_encryptes(self):
        return False

    def is_signed(self):
        return False

    def get_child_count(self):
        return self.mime_object.to_multipart().get_count()

    def get_child(self, idx):
        if idx >= self.get_child_count():
            raise MultipartError
        else:
            prt = self.mime_object.to_multipart().get_part(idx)
            return MimeObject._mk_mime_object(prt, self)

    def has_children(self):
        return True

    def children(self):
        for idx in xrange(self.get_child_count()):
            yield self.get_child(idx)


class Encrypted(Multipart):

    def __init__(self, mime_object, parent=None):
        super(Encrypted, self).__init__(mime_object, parent)

    def is_encryptes(self):
        return True

    def decrypt(self, passphrase=None):
        if not GPG_ENABLED:
            raise PygmiError, "The GnuPGInterface module is not available. Can't decrypt."

        ciphertext = self.get_child(1).get_data()
        
        gnupg = GnuPGInterface.GnuPG()
        if passphrase:
            gnupg.passphrase = passphrase
        
        decrypt_proc = gnupg.run(['--decrypt'], create_fhs=['stdin', 'stdout', 'stderr'])
        decrypt_proc.handles['stdin'].write(ciphertext)
        decrypt_proc.handles['stdin'].close()
        plaintext = decrypt_proc.handles['stdout'].read()
        decrypt_proc.handles['stdout'].close()
        decrypt_proc.wait()

        return plaintext

class Signed(Multipart):

    def __init__(self, mime_object, parent=None):
        super(Signed, self).__init__(mime_object, parent)

    def is_signed(self):
        return True

    def verify(self):
        if not GPG_ENABLED:
            raise PygmiError, "The GnuPGInterface module is not available. Can't decrypt."

        else:
            print "Not implemented yet"
