import struct
from typing import Union, Optional

def cumsum(x):
    return [sum(x[:i]) for i in range(1, len(x)+1)]

class PalmDoc:
    header_info = {
        0: {"offset": 0, "bytes": 32, "dtype": bytes, "content": "name"},
        32: {"offset": 32, "bytes": 2, "dtype": ">H", "content": "attributes"},
        34: {"offset": 34, "bytes": 2, "dtype": ">H", "content": "version"},
        36: {"offset": 36, "bytes": 4, "dtype": ">l", "content": "creation date"},
        40: {"offset": 40, "bytes": 4, "dtype": ">l", "content": "modification date"},
        44: {"offset": 44, "bytes": 4, "dtype": ">l", "content": "last backup date"},
        48: {"offset": 48, "bytes": 4, "dtype": ">L", "content": "modificationNumber"},
        52: {"offset": 52, "bytes": 4, "dtype": ">L", "content": "appInfoID"},
        56: {"offset": 56, "bytes": 4, "dtype": ">L", "content": "sortInfoID"},
        60: {"offset": 60, "bytes": 4, "dtype": bytes, "content": "type"},
        64: {"offset": 64, "bytes": 4, "dtype": bytes, "content": "creator"},
        68: {"offset": 68, "bytes": 4, "dtype": ">L", "content": "uniqueIDseed"},
        72: {"offset": 72, "bytes": 4, "dtype": ">L", "content": "nextRecordListID"},
        76: {"offset": 76, "bytes": 2, "dtype": ">H", "content": "number of Records"},
    }

    def __init__(self, file) -> None:
        self.file_path = file
        with open(file, "rb") as f:
            self.header = f.read(78)
            self.get_metadata()
            self.num_records = self.metadata[76]["value"]
            self.record_info = f.read(self.num_records*8)
            self.get_record_info_list()
            self.record_offsets = [x["record Data Offset"] for x in self.record_info_list]
            self.records = []
            for i in range(self.num_records - 1):
                offset, offset_next = self.record_offsets[i], self.record_offsets[i+1]
                f.seek(offset)
                self.records.append(f.read(offset_next - offset))
            self.records.append(f.read())
            self.record_bytes = [len(record) for record in self.records]
            self.record_unique_ids = [x["UniqueID"] for x in self.record_info_list]

    def get_metadata(self):
        self.metadata = PalmDoc.header_info.copy()
        for k, v in PalmDoc.header_info.items():
            data_temp = self.header[v["offset"]:v["offset"]+v["bytes"]]
            if not v["dtype"] is bytes:
                value_temp = struct.unpack(v["dtype"], data_temp)[0]
            else:
                value_temp = data_temp
            self.metadata[k]["data"] = data_temp
            self.metadata[k]["value"] = value_temp
        return self.metadata

    def get_record_info_list(self):
        self.record_info_list = []
        for i in range(self.num_records):
            self.record_info_list.append({
                "record Data Offset": struct.unpack_from(">L", self.record_info, i*8)[0],
                "record Attributes": self.record_info[i*8+4:i*8+5],
                "UniqueID": struct.unpack(">L", b"\x00"+self.record_info[i*8+5:i*8+8])[0],
            })
        self.metadata[78] = {
            "offset": 78, "bytes": self.num_records*8, "content": "record Info List",
            "dtype": bytes, "data": self.record_info, "value": self.record_info_list
        }
        return self.record_info_list

    def to_file(self, file: Optional[str] = None):
        if file is None:
            file = self.file_path
        self.update()
        with open(file, "wb") as f:
            f.write(self.header)
            f.write(bytes(2))
            for record in self.records:
                f.write(record)

    def add_record(self, record, i: Optional[int] = None,
                   attribute=b"\x00", unique_id: Optional[int] = None):
        if not len(attribute) == 1:
            raise ValueError("length of attribute .neq. 1: {0}".format(attribute))
        if (not unique_id is None) & (unique_id in self.record_unique_ids):
            unique_id = max([x["UniqueID"] for x in self.record_info_list]) + 2
            # logging info
        elif unique_id is None:
            unique_id = max([x["UniqueID"] for x in self.record_info_list]) + 2
        record_info = {
            "record Data Offset": self.record_offsets[-1] + self.record_bytes[-1],
            "record Attributes": attribute,
            "UniqueID": unique_id,
        }
        record_bytes = len(record)
        if i is None:
            self.records.append(record)
            self.record_info_list.append(record_info)
            self.record_bytes.append(record_bytes)
        else:
            self.records.insert(i, record)
            self.record_info_list.insert(i, record_info)
            self.record_bytes.insert(i, record_bytes)
        self.update(record_bytes=False)

    def remove_record(self, i):
        del self.records[i], self.record_info_list[i], self.record_bytes[i]
        self.update(record_bytes=False)
    
    def update_record(self, record, i):
        attribute = self.record_info_list[i]["record Attributes"]
        unique_id = self.record_info_list[i]["UniqueID"]
        self.remove_record(i)
        self.add_record(record, i, attribute, unique_id)
    
    def get_data_from_value(self, value, dtype, size):
        value_type = type(value)
        if value_type is str:
            data = bytes(value.encode())
        elif value_type is bytes:
            data = value
        else:
            data = struct.pack(dtype, value)
        length = len(data)
        data = data[:size] if length > size else data + bytes(size - length)
        return data

    def change_metadata(self, offset, value):
        if not 0 <= offset <= 76:
            raise IndexError("offset must be between 0 and 76, current offset: {0}".format(offset))
        dtype = self.metadata[offset]["dtype"]
        size = self.metadata[offset]["bytes"]
        data = self.get_data_from_value(value, dtype, size)
        self.metadata[offset]["data"] = data
        if dtype is bytes:
            self.metadata[offset]["value"] = data
        else:
            self.metadata[offset]["value"] = struct.unpack(dtype, data)

    def update(self, record_bytes=True):
        self.num_records = len(self.records)
        self.metadata[76]["data"] = struct.pack(">H", self.num_records)
        self.metadata[76]["value"] = self.num_records
        if record_bytes: self.record_bytes = [len(record) for record in self.records]
        offset_0 = 78 + self.num_records*8 + 2
        self.record_offset = cumsum([offset_0] + self.record_bytes[:-1])
        for i in range(self.num_records):
            self.record_info_list[i]["record Data Offset"] = self.record_offset[i]
        self.get_record_info_from_record_info_list()
        self.metadata[78] = {
            "offset": 78, "bytes": self.num_records*8, "content": "record Info List",
            "dtype": bytes, "data": self.record_info, "value": self.record_info_list
        }
        self.header = b"".join([x["data"] for x in self.metadata.values()])
    
    def get_record_info_from_record_info_list(self):
        record_info_temp = [b"".join([
            struct.pack(">L", x["record Data Offset"]),
            x["record Attributes"],
            struct.pack(">L", x["UniqueID"])[1:]
        ]) for x in self.record_info_list]
        self.record_info = b"".join(record_info_temp)
        return self.record_info

class MobiHeader:
    palm_doc_header_info = {
        0: {"offset": 0, "bytes": 2, "dtype": ">H", "content": "Compression"},
        2: {"offset": 2, "bytes": 2, "dtype": ">H", "content": "Unused"},
        4: {"offset": 4, "bytes": 4, "dtype": ">L", "content": "text length"},
        8: {"offset": 8, "bytes": 2, "dtype": ">H", "content": "record count"},
        10: {"offset": 10, "bytes": 2, "dtype": ">H", "content": "record size"},
    }
    palm_doc_header_info_1 = palm_doc_header_info.copy()
    palm_doc_header_info_1.update({
        12: {"offset": 12, "bytes": 4, "dtype": ">L", "content": "Current Position"},
    })
    palm_doc_header_info_2 = palm_doc_header_info.copy()
    palm_doc_header_info_2.update({
        12: {"offset": 12, "bytes": 2, "dtype": ">H", "content": "Encryption Type"},
        14: {"offset": 14, "bytes": 2, "dtype": ">H", "content": "Unknown"},
    })

    mobi_header_info = {
        16: {"offset": 16, "bytes": 4, "dtype": bytes, "content": "identifier"},
        20: {"offset": 20, "bytes": 4, "dtype": ">L", "content": "header length"},
        24: {"offset": 24, "bytes": 4, "dtype": ">L", "content": "Mobi type"},
        28: {"offset": 28, "bytes": 4, "dtype": ">L", "content": "text Encoding"},
        32: {"offset": 32, "bytes": 4, "dtype": ">L", "content": "Unique-ID"},
        36: {"offset": 36, "bytes": 4, "dtype": ">L", "content": "File version"},
        40: {"offset": 40, "bytes": 4, "dtype": ">L", "content": "Ortographic index"},
        44: {"offset": 44, "bytes": 4, "dtype": ">L", "content": "Inflection index"},
        48: {"offset": 48, "bytes": 4, "dtype": ">L", "content": "Index names"},
        52: {"offset": 52, "bytes": 4, "dtype": ">L", "content": "Index keys"},
        56: {"offset": 56, "bytes": 4, "dtype": ">L", "content": "Extra index 0"},
        60: {"offset": 60, "bytes": 4, "dtype": ">L", "content": "Extra index 1"},
        64: {"offset": 64, "bytes": 4, "dtype": ">L", "content": "Extra index 2"},
        68: {"offset": 68, "bytes": 4, "dtype": ">L", "content": "Extra index 3"},
        72: {"offset": 72, "bytes": 4, "dtype": ">L", "content": "Extra index 4"},
        76: {"offset": 76, "bytes": 4, "dtype": ">L", "content": "Extra index 5"},
        80: {"offset": 80, "bytes": 4, "dtype": ">L", "content": "First Non-book index?"},
        84: {"offset": 84, "bytes": 4, "dtype": ">L", "content": "Full Name Offset"},
        88: {"offset": 88, "bytes": 4, "dtype": ">L", "content": "Full Name Length"},
        92: {"offset": 92, "bytes": 4, "dtype": ">L", "content": "Locale"},
        96: {"offset": 96, "bytes": 4, "dtype": bytes, "content": "Input Language"},
        100: {"offset": 100, "bytes": 4, "dtype": bytes, "content": "Output Language"},
        104: {"offset": 104, "bytes": 4, "dtype": ">L", "content": "Min version"},
        108: {"offset": 108, "bytes": 4, "dtype": ">L", "content": "First Image index"},
        112: {"offset": 112, "bytes": 4, "dtype": ">L", "content": "Huffman Record Offset"},
        116: {"offset": 116, "bytes": 4, "dtype": ">L", "content": "Huffman Record Count"},
        120: {"offset": 120, "bytes": 4, "dtype": ">L", "content": "Huffman Table Offset"},
        124: {"offset": 124, "bytes": 4, "dtype": ">L", "content": "Huffman Table Length"},
        128: {"offset": 128, "bytes": 4, "dtype": ">L", "content": "EXTH flags"},
        132: {"offset": 132, "bytes": 32, "dtype": bytes, "content": "Unknown"},
        164: {"offset": 164, "bytes": 4, "dtype": bytes, "content": "Unknown"},
        168: {"offset": 168, "bytes": 4, "dtype": ">L", "content": "DRM Offset"},
        172: {"offset": 172, "bytes": 4, "dtype": ">L", "content": "DRM Count"},
        176: {"offset": 176, "bytes": 4, "dtype": ">L", "content": "DRM Size"},
        180: {"offset": 180, "bytes": 4, "dtype": ">L", "content": "DRM Flags"},
        184: {"offset": 184, "bytes": 8, "dtype": bytes, "content": "Unknown"},
        192: {"offset": 192, "bytes": 2, "dtype": ">H", "content": "First content record number"},
        194: {"offset": 194, "bytes": 2, "dtype": ">H", "content": "Last content record number"},
        196: {"offset": 196, "bytes": 4, "dtype": bytes, "content": "Unknown"},
        200: {"offset": 200, "bytes": 4, "dtype": ">L", "content": "FCIS record number"},
        204: {"offset": 204, "bytes": 4, "dtype": bytes, "content": "Unknown (FCIS record count?)"},
        208: {"offset": 208, "bytes": 4, "dtype": ">L", "content": "FLIS record number"},
        212: {"offset": 212, "bytes": 4, "dtype": bytes, "content": "Unknown (FLIS record count?)"},
        216: {"offset": 216, "bytes": 8, "dtype": bytes, "content": "Unknown"},
        224: {"offset": 224, "bytes": 4, "dtype": bytes, "content": "Unknown"},
        228: {"offset": 228, "bytes": 4, "dtype": ">L", "content": "First Compilation data section count"},
        232: {"offset": 232, "bytes": 4, "dtype": ">L", "content": "Number of Compilation data sections"},
        236: {"offset": 236, "bytes": 4, "dtype": bytes, "content": "Unknown"},
        240: {"offset": 240, "bytes": 4, "dtype": ">L", "content": "Extra Record Data Flags"},
        244: {"offset": 244, "bytes": 4, "dtype": ">L", "content": "INDX Record Offset"},
        248: {"offset": 248, "bytes": 4, "dtype": bytes, "content": "Unknown"},
        252: {"offset": 252, "bytes": 4, "dtype": bytes, "content": "Unknown"},
        256: {"offset": 256, "bytes": 4, "dtype": bytes, "content": "Unknown"},
        260: {"offset": 260, "bytes": 4, "dtype": bytes, "content": "Unknown"},
        264: {"offset": 264, "bytes": 4, "dtype": bytes, "content": "Unknown"},
        268: {"offset": 268, "bytes": 4, "dtype": bytes, "content": "Unknown"},
        272: {"offset": 272, "bytes": 4, "dtype": bytes, "content": "Unknown"},
        276: {"offset": 276, "bytes": 4, "dtype": bytes, "content": "Unknown"},
    }

    id_map_hexstrings = {
        209: 'Tamper Proof Keys (hex)',  # Used by the Kindle (and Android app) for generating book-specific PIDs.
        300: 'Font Signature (hex)',
        403: 'Unknown_(403) (hex)',
        405: 'Unknown_(405) (hex)',  # Unknown (Rent/Borrow flag?) 1 in this field seems to indicate a rental book
        407: 'Unknown_(407) (hex)',
        450: 'Unknown_(450) (hex)',
        451: 'Unknown_(451) (hex)',
        452: 'Unknown_(452) (hex)',
        453: 'Unknown_(453) (hex)',
        536: 'Unknown_(536) (hex)',
        542: 'Unknown_(542) (hex)',  # Some Unix timestamp.	
        547: 'InMemory (hex)',  # String 'I\x00n\x00M\x00e\x00m\x00o\x00r\x00y\x00' found in this record, for KindleGen V2.9 build 1029-0897292
    }

    id_map_strings = {
        1: 'Drm Server Id',
        2: 'Drm Commerce Id',
        3: 'Drm Ebookbase Book Id',
        100: 'Author',
        101: 'Publisher',
        102: 'Imprint',
        103: 'Description',
        104: 'ISBN',
        105: 'Subject',
        106: 'Publishing Date',
        107: 'Review',
        108: 'Contributor',
        109: 'Rights',
        110: 'Subject Code',
        111: 'Type',
        112: 'Source',
        113: 'ASIN',
        114: 'Version Number',
        117: 'Adult',  # Mobipocket Creator adds this if Adult only is checked on its GUI; contents: "yes"	
        118: 'Retail Price',  # As text, e.g. "4.99"	
        119: 'Retail Price Currency',  # As text, e.g. "USD"	
        122: 'Fixed-layout',  # "true"
        123: 'Book-type',  # "comic"
        124: 'Orientation-lock',  # "none", "portrait", "landscape"
        126: 'Original-resolution',  # "1072x1448"
        127: 'zero-gutter',  # "true"
        128: 'zero-margin',  # "true"
        129: 'Metadata Resource URI',
        132: 'Region Magnification',
        200: 'Dict Short Name',
        208: 'Watermark',
        501: 'Document Type',  # PDOC - Personal Doc; EBOK - ebook; EBSP - ebook sample;	
        502: 'Last Update Time',
        503: 'Updated Title',
        504: 'ASIN_(504)',
        508: 'Title file-as',
        517: 'Creator file-as',
        522: 'Publisher file-as',
        524: 'Language_(524)',
        525: 'primary-writing-mode',
        527: 'page-progression-direction',
        528: 'Unknown_Logical_Value_(528)',
        529: 'Original_Source_Description_(529)',
        534: 'Unknown_(534)',
        535: 'Kindlegen BuildRev Number',
    }

    id_map_values = {
        115: 'Sample',
        116: 'Start Reading',  # Position (4-byte offset) in file at which to open when first opened	
        121: 'K8(121) Boundary Section',
        125: 'K8(125) Count of Resources Fonts Images',
        131: 'K8(131) Unidentified Count',
        201: 'Cover Offset',  # Add to first image field in Mobi Header to find PDB record containing the cover image	
        202: 'Thumb Offset',  # Add to first image field in Mobi Header to find PDB record containing the thumbnail cover image	
        203: 'Has Fake Cover',
        204: 'Creator Software',
        205: 'Creator Major Version',
        206: 'Creator Minor Version',
        207: 'Creator Build Number',
        401: 'Clipping Limit',  # Integer percentage of the text allowed to be clipped. Usually 10.	
        402: 'Publisher Limit',
        404: 'Text to Speech Flag',  # 1 - Text to Speech disabled; 0 - Text to Speech enabled
        406: 'Rent/Borrow Expiration Date',  # If this field is removed from a rental, the book says it expired in 1969
    }
    
    def __init__(self, file) -> None:
        self.file_path = file
        self.palm_doc = PalmDoc(self.file_path)
        self.get_metadata()
        self.exth_value = self.metadata["EXTH"]["value"]
        
    def get_metadata(self):
        header = self.palm_doc.records[0]
        # base information
        compression = struct.unpack_from(">H", header, 0)[0]
        if compression == 17480:
            self.metadata = MobiHeader.palm_doc_header_info_2.copy()
        else:
            self.metadata = MobiHeader.palm_doc_header_info_1.copy()
        self.metadata.update(MobiHeader.mobi_header_info.copy())
        for k, v in self.metadata.items():
            data_temp = header[v["offset"]:v["offset"]+v["bytes"]]
            if not v["dtype"] is bytes:
                value_temp = struct.unpack(v["dtype"], data_temp)[0]
            else:
                value_temp = data_temp
            self.metadata[k]["data"] = data_temp
            self.metadata[k]["value"] = value_temp
        header_length = self.metadata[20]["value"]
        # exth header
        self.text_encoding = "UTF-8"
        if self.metadata[28]["value"] == 1252:
            self.text_encoding = "CP1252"
        elif self.metadata[28]["value"] == 65001:
            self.text_encoding = "UTF-8"
        if self.metadata[128]["value"] & 0x40:
            exth_offset = header_length + 16
            exth_length, = struct.unpack_from('>L', header, exth_offset+4)
            # exth_length = ((exth_length + 3) >> 2) << 2  # round to next 4 byte boundary
            exth = header[exth_offset:exth_offset+exth_length]
            exth_value = self.get_exth_value_from_hex(exth)
            self.metadata["EXTH"] = self.get_exth_metadata(exth_value)
        # title
        full_name_offset = self.metadata[84]["value"]
        full_name_length = self.metadata[88]["value"]
        full_name_data = header[full_name_offset:full_name_offset+full_name_length]
        try:
            title = full_name_data.decode(encoding=self.text_encoding)
        except:
            # fix padding between EXTH and title
            full_name_data = header[full_name_offset-4:full_name_offset+full_name_length-4]
            title = full_name_data.decode(encoding=self.text_encoding)
        self.metadata["full_name"] = self.get_title_metadata(title)
        # padding
        self.metadata["padding"] = self.get_padding_metadata()
        return self.metadata
    
    def get_value(self, data, dtype):
        if dtype == str:
            value = data.decode(encoding=self.text_encoding)
        elif dtype == bytes:
            value = data
        elif dtype == list:
            value = self.get_exth_value_from_hex(data)
        else:
            value = struct.unpack(dtype, data)[0]
        return value

    def get_exth_info(self, id, content):
        size = len(content)
        if id in MobiHeader.id_map_strings.keys():
            name = MobiHeader.id_map_strings[id]
            dtype = str
        elif id in MobiHeader.id_map_values.keys():
            name = MobiHeader.id_map_values[id]
            if size == 9:
                dtype = 'B'
            elif size == 10:
                dtype = '>H'
            elif size == 12:
                dtype = '>L'
            else:
                dtype = bytes
        elif id in MobiHeader.id_map_hexstrings.keys():
            name = MobiHeader.id_map_hexstrings[id]
            dtype = bytes
        else:
            name = str(id) + ' (hex)'
            dtype = bytes
        value = self.get_value(content, dtype)
        return name, dtype, value

    def get_exth_value_from_hex(self, exth):
        exth_value = []
        _length, num_items = struct.unpack('>LL', exth[4:12])
        exth = exth[12:]
        pos = 0
        for _ in range(num_items):
            tmpid, size = struct.unpack('>LL', exth[pos:pos+8])
            content = exth[pos + 8: pos + size]
            data = exth[pos: pos + size]
            name, dtype, value = self.get_exth_info(tmpid, content)
            exth_value.append({
                "name": name,
                "id": tmpid,
                "size": size,
                "data": data,
                "dtype": dtype,
                "value": value,
            })
            pos += size
        return exth_value
    
    def get_exth_metadata(self, exth_value):
        exth_data = self.convert_exth_value_to_hex(exth_value)
        exth_offset = self.metadata[20]["value"] + 16
        exth_metadata = {
            "offset": exth_offset,
            "bytes": len(exth_data),
            "dtype": list,
            "content": "exth_header with padding",
            "data": exth_data,
            "value": exth_value,
        }
        return exth_metadata

    def get_title_metadata(self, title):
        data = title.encode(encoding=self.text_encoding)
        length = len(data)
        offset = self.metadata["EXTH"]["offset"] + self.metadata["EXTH"]["bytes"]
        title_metadata = {
            "offset": offset,
            "bytes": length,
            "dtype": str,
            "content": "full_name",
            "data": data,
            "value": title,
        }
        return title_metadata
    
    def get_padding_metadata(self):
        offset = self.metadata["full_name"]["offset"] + self.metadata["full_name"]["bytes"]
        padding = bytes((4 - offset % 4) % 4)
        padding_metadata = {
            "offset": offset,
            "bytes": len(padding),
            "dtype": bytes,
            "content": "padding",
            "data": padding,
            "value": padding,
        }
        return padding_metadata

    def convert_exth_value_to_hex(self, exth_value):
        exth_header_data = b"".join([x["data"] for x in exth_value])
        exth_header_length = len(exth_header_data) + 12
        exth_record_count = len(exth_value)
        padding = bytes((4 - exth_header_length % 4) % 4)
        data = b"".join([
            b"EXTH",
            struct.pack(">LL", exth_header_length, exth_record_count),
            exth_header_data,
            padding
        ])
        return data
    
    def update(self):
        # EXTH flag
        if not "EXTH" in self.metadata.keys():
            self.change_metadata(128, 0)
        else:
            self.change_metadata(128, 80)
        # fix padding between EXTH and title
        self.change_title(self.metadata["full_name"]["value"])
        record0 = b"".join([x["data"] for x in self.metadata.values()])
        self.palm_doc.update_record(record0, 0)
        self.palm_doc.update()

    def change_title(self, title):
        id_list = [x["id"] for x in self.exth_value]
        if 503 in id_list:
            self.change_exth_metadata(503, title)
        else:
            self.add_exth_record(503, title, str)
        self.change_metadata("full_name", title)
        self.update_offset_size()
        self.change_metadata(84, self.metadata["full_name"]["offset"])
        self.change_metadata(88, self.metadata["full_name"]["bytes"])
        self.palm_doc.change_metadata(0, title)

    def update_offset_size(self):
        size_list = [len(x["data"]) for x in self.metadata.values()]
        offset_list = cumsum([0] + size_list[:-1])
        for i, x in enumerate(self.metadata.values()):
            x["offset"] = offset_list[i]
            x["bytes"] = size_list[i]
        self.metadata["padding"] = self.get_padding_metadata()

    def get_data(self, value, dtype):
        if dtype == str:
            data = value.encode(encoding=self.text_encoding)
        elif dtype == bytes:
            data = value
        elif dtype == list:
            data = self.convert_exth_value_to_hex(value)
        else:
            data = struct.pack(dtype, value)
        return data

    def change_metadata(self, id, value):
        dtype = self.metadata[id]["dtype"]
        self.metadata[id]["data"] = self.get_data(value, dtype)
        self.metadata[id]["value"] = value
        self.update_offset_size()

    def change_exth_metadata(self, id, value):
        exth_value = self.metadata["EXTH"]["value"]
        id_list = [x["id"] for x in exth_value]
        i = id_list.index(id)
        dtype = exth_value[i]["dtype"]
        data = self.get_data(value, dtype)
        data = b"".join([struct.pack(">LL", id, len(data) + 8), data])
        exth_value[i]["value"] = value
        exth_value[i]["size"] = len(data)
        exth_value[i]["data"] = data
        self.metadata["EXTH"] = self.get_exth_metadata(exth_value)
        self.update_offset_size()
    
    def add_exth_record(self, id, value, dtype):
        data = self.get_data(value, dtype)
        name, dtype_new, value_new = self.get_exth_info(id, data)
        if (not dtype == dtype_new) or (not value == value_new):
            raise KeyError("dtype does not match id, maybe {2}, (id, dtype): ({0}, {1})".format(id, dtype, dtype_new))
        self.metadata["EXTH"]["value"].append({
            "name": name,
            "id": id,
            "size": len(data),
            "data": data,
            "dtype": dtype,
            "value": value,
        })
        self.metadata["EXTH"] = self.get_exth_metadata(self.metadata["EXTH"]["value"])
        self.update_offset_size()

    def remove_exth_record(self, id, type="id"):
        exth_value = self.metadata["EXTH"]["value"]
        if type == "id":
            id_list = [x["id"] for x in exth_value]
            while id in id_list:
                i = id_list.index(id)
                del id_list[i]
                del exth_value[i]
        elif type == "i":
            del exth_value[i]
        self.metadata["EXTH"] = self.get_exth_metadata(exth_value)
        self.update_offset_size()
    
    def get_exth_value_by_id(self, id):
        exth_value = self.metadata["EXTH"]["value"]
        id_list = [x["id"] for x in exth_value]
        i = id_list.index(id)
        return exth_value[i]["value"]

    def to_file(self, file: Optional[str] = None):
        self.update()
        self.palm_doc.to_file(file)