from libc.stdio cimport fopen, FILE, stdin, stdout

cdef extern from "gmime/gmime.h":

    ctypedef long time_t

    ctypedef struct guint32: 
        pass

    ctypedef extern struct GType:
        pass

    ctypedef extern struct GObject:
        pass

    ctypedef extern struct GByteArray:
        char *data
        unsigned int  len

    ctypedef struct GPtrArray:
        pass

    ctypedef struct GError:
        char *message

    ctypedef struct GMimeReferences:
        pass
                                                             
    ctypedef enum GMimeContentEncoding:
        GMIME_CONTENT_ENCODING_DEFAULT
        GMIME_CONTENT_ENCODING_7BIT
        GMIME_CONTENT_ENCODING_8BIT
        GMIME_CONTENT_ENCODING_BINARY
        GMIME_CONTENT_ENCODING_BASE64
        GMIME_CONTENT_ENCODING_QUOTEDPRINTABLE
        GMIME_CONTENT_ENCODING_UUENCODE

    ctypedef enum GMimeStreamBufferMode:
        GMIME_STREAM_BUFFER_CACHE_READ
        GMIME_STREAM_BUFFER_BLOCK_READ
        GMIME_STREAM_BUFFER_BLOCK_WRITE

    ctypedef struct GMimeStream:
        pass

    ctypedef struct GMimeStreamFilter:
        pass

    ctypedef struct GMimeFilter:
        pass

    ctypedef struct GMimeDataWrapper:
        pass

    ctypedef struct GMimeParser:
        pass

    ctypedef struct GMimeObject:
        pass

    ctypedef struct GMimePart:
        pass

    ctypedef struct GMimeMultipart:
        pass

    ctypedef struct GMimeMultipartEncrypted:
        pass

    ctypedef struct GMimeMultipartSigned:
        pass

    ctypedef struct GMimeMessage:
        pass

    ctypedef struct GMimeMessagePart:
        pass

    ctypedef struct GMimeContentType:
        pass

    ctypedef struct GMimeParam:
        pass

    ctypedef struct GMimeContentDisposition:
        pass

    ctypedef struct GMimeHeaderList:
        pass

    ctypedef struct GMimeHeader:
        pass

    ctypedef struct GMimeHeaderIter:
        GMimeHeaderList *hdrlist
        GMimeHeader *cursor
        guint32 version

    ctypedef struct CInternetAddress "InternetAddress":
        pass

    ctypedef struct CInternetAddressGroup "InternetAddressGroup": 
        pass

    ctypedef struct CInternetAddressMailbox "InternetAddressMailbox":
        pass

    ctypedef struct CInternetAddressList "InternetAddressList":
        pass

    ctypedef struct GMimeCipherContext:
        pass

    ctypedef struct GMimeGpgContext:
        pass


    ctypedef enum GMimeCipherHash:
        GMIME_CIPHER_HASH_DEFAULT
        GMIME_CIPHER_HASH_MD2
        GMIME_CIPHER_HASH_MD5
        GMIME_CIPHER_HASH_SHA1
        GMIME_CIPHER_HASH_SHA224
        GMIME_CIPHER_HASH_SHA256
        GMIME_CIPHER_HASH_SHA384
        GMIME_CIPHER_HASH_SHA512
        GMIME_CIPHER_HASH_RIPEMD160
        GMIME_CIPHER_HASH_TIGER192
        GMIME_CIPHER_HASH_HAVAL5160

    ctypedef enum GMimeSignatureStatus:
        GMIME_SIGNATURE_STATUS_NONE
        GMIME_SIGNATURE_STATUS_GOOD
        GMIME_SIGNATURE_STATUS_BAD
        GMIME_SIGNATURE_STATUS_UNKNOWN

    ctypedef enum GMimeSignerStatus:
        GMIME_SIGNER_STATUS_NONE
        GMIME_SIGNER_STATUS_GOOD
        GMIME_SIGNER_STATUS_BAD
        GMIME_SIGNER_STATUS_ERROR

    ctypedef struct GMimeSigner:
        GMimeSigner *next
        unsigned int status
        unsigned int errors
        unsigned int trust
        char *fingerprint
        time_t created
        time_t expires
        char *keyid
        char *name

    ctypedef struct GMimeSignatureValidity:
        GMimeSignatureStatus status
        GMimeSigner *signers
        char *details

    ctypedef struct GMimeSession:
        pass

    ctypedef struct GMimeSessionSimple:
        pass

    ctypedef void (*GMimeSimpleRequestPasswdFunc)(GMimeSession *session,
                                                  char *prompt,\
                                                  bint secret,\
                                                  char *item,\
                                                  GError **err)

    ctypedef void (*GMimeSimpleForgetPasswdFunc)(GMimeSession *session,
                                                 char *item,\
                                                 GError **err)

    ctypedef void (*GMimeSimpleIsOnlineFunc) ()



    void g_mime_init (int)

    time_t g_mime_utils_header_decode_date (char *str, int *tz_offset)
    char* g_mime_utils_header_format_date (time_t date, int tz_offset)
    char* g_mime_utils_generate_message_id (char *fqdn)
    char* g_mime_utils_decode_message_id (char *message_id)
    char* g_mime_references_get_message_id (GMimeReferences *ref)
    GMimeReferences* g_mime_references_get_next (GMimeReferences *ref)
    GMimeReferences*    g_mime_references_decode (char *text)
    void  g_mime_references_append (GMimeReferences **refs, char *msgid)
    void  g_mime_references_clear (GMimeReferences **refs)
    void  g_mime_references_free (GMimeReferences *refs)
    char* g_mime_utils_header_fold (char *str)
    char* g_mime_utils_header_printf (char *format, ...)
    char* g_mime_utils_quote_string (char *str)
    void  g_mime_utils_unquote_string (char *str)
    bint g_mime_utils_text_is_8bit (unsigned char *text, size_t len)
    GMimeContentEncoding g_mime_utils_best_encoding (unsigned char *text,\
                                                         size_t len)
    char* g_mime_utils_decode_8bit (char *text, size_t len)
    char* g_mime_utils_header_decode_text (char *text)
    char* g_mime_utils_header_encode_text (char *text)
    char* g_mime_utils_header_decode_phrase (char *phrase)
    char* g_mime_utils_header_encode_phrase (char *phrase)
    char* g_mime_utils_structured_header_fold (char *str)
    char* g_mime_utils_unstructured_header_fold (char *str)

    GType g_mime_session_get_type ()

    GObject *g_object_new (GType object_type, char *first_property_name)

    GByteArray  *g_byte_array_new     ()
    GByteArray  *g_byte_array_append     (GByteArray *array, unsigned char *data, int len)

    char *g_mime_session_request_passwd  (GMimeSession *session,\
                                          char *prompt,\
                                          bint secret,\
                                          char *item,\
                                          GError **err)
    void g_mime_session_forget_passwd   (GMimeSession *session,\
                                         char *item,\
                                         GError **err)
    bint g_mime_session_is_online (GMimeSession *session)

    void g_mime_session_simple_set_request_passwd (GMimeSessionSimple *session, \
                                                   void *request_passwd_func)
    void g_mime_session_simple_set_forget_passwd (GMimeSessionSimple *session, \
                                                  void *forget_passwd_func)
    void g_mime_session_simple_set_is_online (GMimeSessionSimple *session, \
                                              void *is_online_func)

    GMimeCipherContext * g_mime_gpg_context_new (GMimeSession *session,\
                                                 char *path)
    bint g_mime_gpg_context_get_always_trust (GMimeGpgContext *ctx)
    void g_mime_gpg_context_set_always_trust (GMimeGpgContext *ctx,\
                                              bint always_trust)


    ssize_t     g_mime_stream_read   (GMimeStream *stream,\
                                      char *buf, \
                                      size_t len)
    ssize_t     g_mime_stream_length  (GMimeStream *stream)
    int         *g_mime_stream_reset (GMimeStream *stream)
    signed long long g_mime_stream_tell (GMimeStream *stream)
    GMimeStream *g_mime_stream_file_new (FILE*)
    GMimeStream *g_mime_stream_mem_new ()
    GMimeStream *g_mime_stream_mem_new_with_byte_array (GByteArray *array)
    GByteArray *g_mime_stream_mem_get_byte_array (GMimeStream *stream)
    ssize_t     g_mime_stream_buffer_gets (GMimeStream *stream, char *buf, size_t max)
    GMimeStream*        g_mime_stream_buffer_new            (GMimeStream *source, GMimeStreamBufferMode mode)
    ssize_t     g_mime_stream_length (GMimeStream *stream)
    void        g_mime_stream_flush (GMimeStream *stream)

    GMimeStream*        g_mime_stream_filter_new            (GMimeStream *stream)
    int                 g_mime_stream_filter_add            (GMimeStreamFilter *stream, GMimeFilter *filter)

    GMimeFilter*        g_mime_filter_crlf_new              (bint, bint)
    GMimeFilter*        g_mime_filter_charset_new           (char *from_charset, char *to_charset)

    GMimeContentType *g_mime_content_type_new (char*, char*)
    GMimeContentType*   g_mime_content_type_new_from_string (char *str)
    char*               g_mime_content_type_to_string       (GMimeContentType *mime_type)
    char*         g_mime_content_type_get_media_type  (GMimeContentType *mime_type)
    char*         g_mime_content_type_get_media_subtype (GMimeContentType *mime_type)
    GMimeParam*   g_mime_content_type_get_params      (GMimeContentType *mime_type)
    char*         g_mime_content_type_get_parameter   (GMimeContentType *mime_type, char *attribute)

    GMimeParam*   g_mime_param_next                   (GMimeParam *param)
    char*         g_mime_param_get_name               (GMimeParam *param)
    char*         g_mime_param_get_value              (GMimeParam *param)

    GMimeContentDisposition* g_mime_content_disposition_new_from_string (char *str)
    char*         g_mime_content_disposition_get_disposition (GMimeContentDisposition *disposition)
    GMimeParam*   g_mime_content_disposition_get_params (GMimeContentDisposition *disposition)
    char*         g_mime_content_disposition_get_parameter (GMimeContentDisposition *disposition, char *attribute)
    char*         g_mime_content_disposition_to_string (GMimeContentDisposition *disposition, bint fold)

    GMimeHeaderIter*      g_mime_header_iter_new           ()
    bint          g_mime_header_iter_first            (GMimeHeaderIter *iter)
    bint          g_mime_header_iter_last             (GMimeHeaderIter *iter)
    bint          g_mime_header_iter_next             (GMimeHeaderIter *iter)
    bint          g_mime_header_iter_prev             (GMimeHeaderIter *iter)
    bint          g_mime_header_iter_is_valid         (GMimeHeaderIter *iter)
    char*         g_mime_header_iter_get_name         (GMimeHeaderIter *iter)
    char*         g_mime_header_iter_get_value        (GMimeHeaderIter *iter)
    char*         g_mime_header_list_get              (GMimeHeaderList *headers, char *name)
    bint          g_mime_header_list_get_iter         (GMimeHeaderList *headers, GMimeHeaderIter *iter)

    char *        internet_address_get_name           (CInternetAddress *ia)
    char *        internet_address_to_string          (CInternetAddress *ia, bint encode)

    CInternetAddress *   internet_address_group_new          (char *name)
    CInternetAddressList * internet_address_group_get_members (CInternetAddressGroup *group)
    void                internet_address_group_set_members  (CInternetAddressGroup *group, CInternetAddressList *members)
    int                 internet_address_group_add_member   (CInternetAddressGroup *group, CInternetAddress *member)

    CInternetAddress *   internet_address_mailbox_new        (char *name, char *addr)
    char *        internet_address_mailbox_get_addr   (CInternetAddressMailbox *mailbox)
    void                internet_address_mailbox_set_addr   (CInternetAddressMailbox *mailbox, char *addr)


    CInternetAddressList * internet_address_list_new         ()
    int                 internet_address_list_length        (CInternetAddressList *list)
    void                internet_address_list_clear         (CInternetAddressList *list)
    int                 internet_address_list_add           (CInternetAddressList *list, CInternetAddress *ia)
    void                internet_address_list_insert        (CInternetAddressList *list, int index, CInternetAddress *ia)
    bint            internet_address_list_remove        (CInternetAddressList *list, CInternetAddress *ia)
    bint            internet_address_list_remove_at     (CInternetAddressList *list, int index)
    bint            internet_address_list_contains      (CInternetAddressList *list, CInternetAddress *ia)
    int             internet_address_list_index_of      (CInternetAddressList *list, CInternetAddress *ia)
    CInternetAddress *   internet_address_list_get_address   (CInternetAddressList *list, int index)
    void                internet_address_list_set_address   (CInternetAddressList *list, int index, CInternetAddress *ia)
    void                internet_address_list_prepend       (CInternetAddressList *list, CInternetAddressList *prepend)
    void                internet_address_list_append        (CInternetAddressList *list, CInternetAddressList *append)
    char *              internet_address_list_to_string     (CInternetAddressList *list, bint encode)
    CInternetAddressList * internet_address_list_parse_string (char *str)
    void                internet_address_list_writer        (CInternetAddressList *list, char *str)




    GMimeObject *g_mime_object_new (GMimeContentType*)
    char        *g_mime_object_to_string (GMimeObject *object)
    ssize_t     *g_mime_object_write_to_stream  (GMimeObject *object, \
                                                  GMimeStream *stream)
    char*       g_mime_object_get_content_type_parameter (GMimeObject *object,\
                                                          char* name)
    char*       g_mime_object_get_headers           (GMimeObject *object)
    GMimeHeaderList* g_mime_object_get_header_list       (GMimeObject *object)


    char*         g_mime_message_get_sender           (GMimeMessage *message)
    char*         g_mime_message_get_reply_to         (GMimeMessage *message)
    char*         g_mime_message_get_subject          (GMimeMessage *message)
    char*         g_mime_message_get_date_as_string   (GMimeMessage *message)
    char*         g_mime_message_get_message_id       (GMimeMessage *message)
    GMimeObject*  g_mime_message_get_mime_part        (GMimeMessage *message)


    GMimeMessagePart* g_mime_message_part_new_with_message \
                      (char *subtype,\
                       GMimeMessage *message)
    GMimeMessage*  g_mime_message_part_get_message (GMimeMessagePart *part)

    int           g_mime_multipart_get_count (GMimeMultipart *multipart)
    GMimeObject*  g_mime_multipart_get_part (GMimeMultipart *multipart, \
                                             int index)
    GMimeObject*  g_mime_multipart_get_subpart_from_content_id \
                 (GMimeMultipart *multipart, char *content_id)

    GMimeMultipartEncrypted * g_mime_multipart_encrypted_new ()
    int g_mime_multipart_encrypted_encrypt  (GMimeMultipartEncrypted *mpe, \
                                             GMimeObject *content, \
                                             GMimeCipherContext *ctx, \
                                             bint sign, \
                                             char *userid, \
                                             GPtrArray *recipients, \
                                             GError **err)
    GMimeObject * g_mime_multipart_encrypted_decrypt \
                (GMimeMultipartEncrypted *mpe, \
                 GMimeCipherContext *ctx, \
                 GError **err)
    GMimeSignatureValidity * g_mime_multipart_encrypted_get_signature_validity \
        (GMimeMultipartEncrypted *mpe)

    GMimeMultipartSigned * g_mime_multipart_signed_new      ()
    int                 g_mime_multipart_signed_sign        (GMimeMultipartSigned *mps, \
                                                             GMimeObject *content, \
                                                             GMimeCipherContext *ctx, \
                                                             char *userid, \
                                                             GMimeCipherHash hash, \
                                                             GError **err)
    GMimeSignatureValidity * g_mime_multipart_signed_verify (GMimeMultipartSigned *mps, \
                                                             GMimeCipherContext *ctx, \
                                                             GError **err)


    char *        g_mime_part_get_content_description (GMimePart *mime_part)
    char *        g_mime_part_get_content_id          (GMimePart *mime_part)
    char *        g_mime_part_get_content_md5         (GMimePart *mime_part)
    bint            g_mime_part_verify_content_md5      (GMimePart *mime_part)
    char *        g_mime_part_get_content_location    (GMimePart *mime_part)
    GMimeContentEncoding  g_mime_part_get_content_encoding  (GMimePart *mime_part)
    char *        g_mime_part_get_filename            (GMimePart *mime_part)



    GMimeDataWrapper*   g_mime_part_get_content_object      (GMimePart *mime_part)

    GMimeDataWrapper *  g_mime_data_wrapper_new_with_stream (GMimeStream *stream, GMimeContentEncoding encoding)
    ssize_t             g_mime_data_wrapper_write_to_stream (GMimeDataWrapper *wrapper, GMimeStream *stream)

    GMimeParser *g_mime_parser_new_with_stream (GMimeStream*)
    GMimeObject *g_mime_parser_construct_part (GMimeParser*)
    GMimeMessage *g_mime_parser_construct_message (GMimeParser*)

    GMimeStreamFilter *GMIME_STREAM_FILTER (GMimeStream*)

    GMimeSession *GMIME_SESSION (GObject*)
    bint GMIME_IS_SESSION (GObject*) 
    GMimePart      *GMIME_PART        (GMimeObject*)
    bint           GMIME_IS_PART        (GMimeObject*)
    GMimeObject    *GMIME_OBJECT      (void*)
    bint           GMIME_IS_MULTIPART (GMimeObject*)
    GMimeMultipart *GMIME_MULTIPART   (GMimeObject*)
    bint           GMIME_IS_MULTIPART_ENCRYPTED (GMimeObject*)
    GMimeMultipartEncrypted *GMIME_MULTIPART_ENCRYPTED   (GMimeObject*)
    bint           GMIME_IS_MULTIPART_SIGNED (GMimeObject*)
    GMimeMultipartSigned *GMIME_MULTIPART_SIGNED   (GMimeObject*)
    bint           GMIME_IS_MESSAGE (GMimeObject*)
    GMimeMessage   *GMIME_MESSAGE   (GMimeObject*)
    bint           GMIME_IS_MESSAGE_PART (GMimeObject*)
    GMimeMessagePart   *GMIME_MESSAGE_PART   (GMimeObject*)
    bint    GMIME_IS_CIPHER_CONTEXT (void*)
    GMimeCipherContext *GMIME_CIPHER_CONTEXT (void*)
    bint    GMIME_IS_GPG_CONTEXT (GMimeCipherContext*)
    GMimeGpgContext *GMIME_GPG_CONTEXT (GMimeCipherContext*)
    GMimeSession *GMIME_SESSION (GObject*)
    GMimeSessionSimple *GMIME_SESSION_SIMPLE (GMimeSession*)
    bint GMIME_IS_SESSION_SIMPLE (GMimeSession*)

    
