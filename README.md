Python Bindings for GMime
=========================

This is a module for fast MIME-parsing and (in the future) generation
in python. It is free software, licensed under the GNU General Public
License v. 2 (or higher).

Included files
--------------

This package offers two libraries:

  * pygmi: a high-level wrapper around the gmime bindings
    (gmimelib). The API here should stay constant regardless of
    changes to the bindings (such as a change from gmime-2.4 to
    gmime-2.6). Pygmi is designed to be pythonic and similar to
    pure-python email.Parser and email.Message classes. (A few changes
    are introduced to make it more consistent and avoid the oddness of
    functions that could return either a string or a list, as will
    sometimes happen with email.Parser).

    This is the interface you most likely want to use.

  * gmimelib: a very low-level binding to GMime 2.4. This is, at the
    moment, subject to change and is undocumented. It is built using
    Cython (see below for building instructions). Unless you have some
    specific low-level task you want to accomplish in python, you
    probably *don't* want to use this.

    If you do want to use this, or work on debugging it, you can do
    something like:

        >>> from pygmi import gmimelib

    or, if you already have pygmi imported:

        >>> gm = pygmi.gmimelib



Instructions for building and installing
----------------------------------------

Pygmi depends on the gmimelib module, which must be compiled, so you
can't just run this straight from the source directory.  You will need
Cython (>=0.14) and gmime-2.4 (accessable by pkg-config).

In the root directory just type

    python setup.py install

There will be gcc compiler warnings. You've been warned.


Using Pygmi
-----------

Pygmi is currently only usable for email parsing and
reading. Generation will be added soon.

The following is the beginning of a sample interactive session, using
pygmi

    >>> import pygmi
    >>> p = pygmi.Parser()
    >>> p.read_file("mailfile.rfc822")
    >>> msg = p.parse()

`msg` will be a member of the MimeObject class, or one of its
subclasses (Part, Multipart, Message, MessagePart). you can test which
one of its subclasses it is by using the `is_part()`,
`is_multipart()`, `is_message()`, `is_message_part()` functions. Or
you could use python's isinstance function.

Any MimeObject can be test for having children (mime parts), or
headers. Note that unlike in email.Parser, a plain text message will
still have one child: the mime part containing the message.

`msg.has_children()` will tell you whether there are any children.

`msg.get_child_count()` will tell you how many.

`msg.get_child(n)` will return the nth child. 

`msg.children()` will return a generator that generates all the
children.

`msg.walk()` will return a generator that will walk recursively
through all children and subchildren.

`msg.get_headers()` will return a Header generator. You can either
walk through the headers, or request one via `hdrs.get('name').

At any point, if you get to a MimeObject that does not have children
(a Part object), you can retrieve the information (text or binary)
from it, through `.get_data()`.

Other functions are still undocumented. Use ipython for tab-completion
or look through the source. They'll be documented soon.
