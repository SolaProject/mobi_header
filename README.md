# mobi_header
A python library for reading/editing mobi/azw3 metadata.

**Install:**  `pip install mobi_header`

# class

## MobiHeader

**variables:**

* file_path: str, path of mobi/azw3 file.
* palm_doc: a PalmDoc object, contain palmdoc's header and records.
* metadata: a python dict, use offset as key, the metadata of file.
* exth_value: a python list, the exth metadata of file.

**method:**

* change_title(title : str):
  
    ​	change the title of metadata.

* change_metadata(id : int, value):
  
    ​	change the mobi metadata. the value will be convert to origin dtype.

* change_exth_metadata(id : int, value):
  
    ​	change the mobi exth metadata. the value will be convert to origin dtype.

* get_exth_value_by_id(id : int):
  
    ​	return the value of id in exth metadata.

* to_file(file : [str, None] = None):
  
    ​	write metadata to file. Default write to origin file.

About metadata and exth-metadata, the detail see [here](https://wiki.mobileread.com/wiki/Mobi#EXTH_Header)

## Example

```python
from mobi_header import MobiHeader
foo = MobiHeader("example.azw3")
foo.change_exth_metadata(501, "PDOC")
foo.to_file()
```