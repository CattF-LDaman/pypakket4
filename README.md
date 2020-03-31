# PyPakket4
**Archive file format in Python 3**

## About

PyPakket4 is an archive file format I created to improve some of my skills and simply as a challenge to see if I could pull it off

I created it with certain things in mind including:
 - Relatively stable memory usage
 - Compression
 - Checksum of some kind
 - AES Encryption
 
 Preferred file extension is .pyp4
 
 ### Implementation details
 
 AES Encryption using pycryptodome
  - Random IV per package, included in file header
  - AES CFB
  - Creator class receives string as input which then gets hashed (SHA-512), first 16 bytes are used
 
 Compression (DEFLATE, INFLATE) using zlib
 
 SHA-256 hash of file is stored in file entry in package header, when file is extracted it's hash can be compared to the one stored in package header
 
 # Requirements
 See requirements.txt
 
 # TO-DO
 - Interface for easier and more rugged extraction and creation
 - GUI?
 - Better TO-DO list (:
 
 # License
 See LICENSE
