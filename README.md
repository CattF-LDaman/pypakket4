#DO NOT USE, MAJOR SECURITY FLAWS

# PyPakket4
**Archive file format in Python 3**

## About

PyPakket4 is an archive file format I created to improve some of my skills and simply as a challenge to see if I could pull it off

I created it with certain things in mind including:
 - Relatively stable memory usage
 - Compression
 - Checksum of some kind
 - AES Encryption
 - Decent package size to original size ratio (using TestDir with test.py, PACKAGE: 3KB, NORMAL: 29KB)
 
 Preferred file extension is .pyp4
 
 ### Implementation details
 
 AES Encryption using pycryptodome
  - Random IV per package, included in file header
  - AES CFB
  - Crypto functions receive string as input which then gets hashed and used as key (blake2b, digest_size = 16)
 
 Compression (DEFLATE, INFLATE) using zlib
 
 blake2b hash of file is stored in file entry in package header, when file is extracted its hash can be compared to the one stored in package header
 
 # Requirements
 see requirements.txt
 
 # Examples
 
DIR is the directory you want to archive eg. CoolDocuments

OUTF is the name/path of the output package file eg. CoolDocuments.pyp4 (name and extension don't really matter)

KEY is a string used to encrypt file contents and some information stored in header
```python
from PyPakket4 import PakketCreate

p = PakketCreate.creator.Creator("DIR")
p.create_package_file("OUTF",encryption_key="KEY",allow_overwrite=True)
p.close()
```
----
Extraction using some of the example values from before

NEWDIR is the directory where extracted files will be placed
```python
from PyPakket4 import PakketExtract

px = PakketExtract.extractor.Extractor("CoolDocuments.pyp4",crypto_key="KEY")
px.extract_package("NEWDIR",allow_overwrites=True)
px.close()
```

 
 # TO-DO
/
 
 # License
 MIT License
 
 see LICENSE
