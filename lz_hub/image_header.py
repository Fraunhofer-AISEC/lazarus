import math
import struct


class ImageHeaderException(Exception):
    pass


class ImageHeader:
    __HEADER_LEN = 0x800

    def __init__(self, header_bytes):
        if len(header_bytes) != self.__HEADER_LEN:
            raise ImageHeaderException(
                "Image header has unexpected size (expected={}, got={})"
                .format(self.__HEADER_LEN, len(header_bytes)))
        self.__header = header_bytes

    def version(self):
        try:
            version = struct.unpack('I', self.__header[40:44])
            version = version[0]
            major = str(math.trunc(version / 0x10000))
            minor = str(version % 0x1000)
            return major + "." + minor
        except Exception as e:
            raise ImageHeaderException(
                "Invalid format of version field") from e

    def issue_time(self):
        try:
            time = struct.unpack('Q', self.__header[48:56])
            return time[0]
        except Exception as e:
            raise ImageHeaderException(
                "Invalid format of issue_time field") from e

    def name(self):
        try:
            return self.__header[8:40].decode("utf-8")
        except Exception as e:
            raise ImageHeaderException(
                "Invalid format of name field") from e
