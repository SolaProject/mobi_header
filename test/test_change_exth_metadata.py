from mobi_header import MobiHeader
from pprint import pprint

foo = MobiHeader("./example.azw3")
print(foo.get_exth_value_by_id(501))
foo.change_exth_metadata(501, "EBOK")
foo.to_file()

bar = MobiHeader("./example.azw3")
print(bar.get_exth_value_by_id(501))

pprint(bar.palm_doc.metadata)
pprint(bar.metadata)