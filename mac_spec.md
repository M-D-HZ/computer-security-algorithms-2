# HTTP MAC Spec

This spec documents a MAC authentication format for securing HTTP traffic. It is unofficial and solely for educational
purposes in the Computer and Network Security course at the University of Antwerp.

## Overview of Request and Response Headers

### Client
The HTTP client authenticates the request by adding the following HTTP headers:

```
Authorization : <Authorization>
X-Authorization-Timestamp : <Unix Timestamp In Seconds>
```

The HTTP client must **not** add the following HTTP Header to the request: \
X-Authenticated-Id (reserved for internal server to server communication)

### Server

If the server authenticates the request successfully, it will add the following HTTP headers to the response:

```
Authorization: <Authorization>
X-Authorization-Timestamp : <Unix Timestamp In Seconds>
```

The client should verify the response MAC which authenticates the response body back from the server.

### Unauthorized

If client or server cannot authenticate the received HTTP message, they will send a response consisting of:

```
Code : 401
Body : 'Not authorized' if server, 'Server response not authorized' if client
Headers : ResponseHeaders
```

With the ResponseHeaders being:

```
Content-Type : 'text/html'
Date : datetime in '%a, %d %b %Y %H:%M:%S %Z' format
Connection: 'close'
WWW-Authenticate : SupportedAuthenticationAlgorithmName [ + "," + SupportedAuthenticationAlgorithmName, for all supported authentication methods]
```

## Overview of Authorization Header and MAC

The pseudocode below illustrates construction of the HTTP "Authorization" header and MAC:

```
Authorization = AlgorithmName + " " +
                "keyid=" + DoubleQuoteEnclose( KeyingIdentificationMaterial ) + "," +
                "nonce=" + DoubleQuoteEnclose( Nonce ) + "," +
                "headers=" + DoubleQuoteEnclose( HeaderNames ) + "," +
                "mac=" + DoubleQuoteEnclose( MAC ) 

HeaderNames = "" or
    HTTP-Header-Name [ + ";" + HTTP-Header-Name, for all headers in HTTP message]
    (sorted alphabetically)
                
MAC = HEXSTRING( HASHED ( SecretKey, Nonce, StringToAuth ) )

StringToAuth = [ HTTP-Verb + "\n" + , if HTTP request]
   [ Host + "\n" + , if HTTP request]
   [ Path + "\n" + , if HTTP request]
   Headers
   [ + "\n" + Content, if Content-Length > 0 ]
   
Headers = Lowercase( HTTP-Header-Name ) + ":" + HTTP-Header-Value 
   [ + "\n" + Lowercase( HTTP-Header-Name ) + ":" + HTTP-Header-Value, for all headers in HTTP message]
   ( must be in the same order as HeaderNames )

```

The **authentication related headers should be included** in "Headers" and "HeaderNames". The MAC must be added to the "Authorization" header after creating it.

### Authorization Header

The value of the `Authorization` header contains the following attributes:

* `keyid`: The key's unique identifier, which is an arbitrary string
* `nonce`:  The used nonce in the generation of the MAC
* `headers`: A **sorted** list of all HTTP headers that are included and used in the MAC base string. These are separated with ";"
* `MAC`: The Message Authentication Code (in hex-string format) as described below.

Each attribute value should be enclosed in double quotes.

Note that the name of this (standard) header is misleading - it carries authentication information.

#### MAC

The MAC is a hashed hexdigest (hex-string format) generated from the following parts:

* `SecretKey`: The used secret key
* `Nonce`: A random value of length equal to the blocksize of the used hashing algorithm
* `StringToAuth`: The string being hashed as described below

#### Secret Key

The secret key that is used can be of any size bigger than 8 bits.

#### String To Authenticate

The base string is a concatenated string generated from the following parts:

* `HTTP-Verb`: The uppercase HTTP request method e.g. "GET", "POST". Not present with an HTTP response.
* `Host`: The HTTP request hostname. Not present with an HTTP response.
* `Path`: The HTTP request path with leading slash, e.g. `/resource/11`. Not present with an HTTP response.
* `Headers`: The header names and values specified as in the header's parameter (same order) of the Authorization header. Names should be lowercase, separated from value by a colon and the value followed by a newline so each extra header is on its own line. If there are no added signed headers, an empty line should **not** be added to the signature base string.
* `Content`: The bytestring of the raw body of the HTTP message that has a body. Omit if Content-Length is 0.
  
#### X-Authorization-Timestamp Header

A Unix timestamp (**integer** seconds since Jan 1, 1970 UTC). If this value differs by more than 900 seconds (15 minutes) from the time of the server, the request will be rejected.

#### X-Authenticated-Id Header

If the X-Authenticated-Id is present in the message, the client implementing the validation of the message should **reject** the message and return "unauthenticated". This header is reserved for servers or proxies who want to validate messages and forward messages to backends. Backends can read this added header to understand if it was authenticated. Use this with caution and careful consideration as adding this header only guarantees it was authenticated to that ID.
