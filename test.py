
from PyPakket4 import *

p = PakketCreate.creator.Creator("TestDir")
p.create_package_file("TestDir.pyp4",encryption_key="TestKey",metadata={"TestExtraData":'A value',"AnotherPieceOfData":2004},allow_overwrite=True)
p.close()

print("--- TEST BORDER ---")

px = PakketExtract.extractor.Extractor("TestDir.pyp4",crypto_key="TestKey")
px.extract_package("TestDir_extract",allow_overwrites=True,add_metadata_file=True)
px.close()
