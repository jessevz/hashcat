#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: hansvh <6390369+hans-vh@users.noreply.github.com>
# Version: 0.0.7
# License: MIT

"""
Files can be found here:
Android: /data/data/com.lastpass.lpandroid/files
Others: See https://support.lastpass.com/help/where-is-my-lastpass-data-stored-on-my-computer-lp070008

Newer Chromium based extensions no longer use SQLite, they keep the vault in
Chrome's IndexedDB, which is a LevelDB store. Point this script at the
directory (or at a single .log/.ldb file inside it), e.g.:

  ~/.config/google-chrome/Default/IndexedDB/
      chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0.indexeddb.leveldb/

Values too large for LevelDB are written to the sibling .indexeddb.blob
directory instead, that one is picked up automatically. Pass --debug to see
which files were read and how.

Tested OK with:
- LastPass for Android (com.lastpass.lpandroid) v5.12.0.10004
- LastPass for Chrome v4.101.1
- LastPass for Opera v4.101.1
- LastPass for Firefox v4.101.0
"""

import os
import re
import struct
import sys
import sqlite3
from base64 import b64decode
from re import search

# Default used when the vault does not carry an explicit iterations value
DEFAULT_ITERATIONS = 100100

# LastPass stores the encrypted account e-mail as !<IV_base64>|<ciphertext_base64>
_B64 = rb"[A-Za-z0-9+/]+={0,2}"
CBC_BLOB_RE = re.compile(rb"!(" + _B64 + rb")\|(" + _B64 + rb")")
CBC_BLOB_UTF16_RE = re.compile(
    rb"!\x00((?:[A-Za-z0-9+/]\x00)+(?:=\x00){0,2})\|\x00((?:[A-Za-z0-9+/]\x00)+(?:=\x00){0,2})"
)

# Field names the Chromium extension uses inside the IndexedDB records
ENCRYPTED_USERNAME_FIELDS = ("encryptedUsername",)
ITERATIONS_FIELDS = ("iterations", "key_iter", "keyIterations")

# LevelDB write ahead log constants, see leveldb/db/log_format.h
LOG_BLOCK_SIZE = 32768
LOG_HEADER_SIZE = 7
LOG_TYPE_ZERO = 0
LOG_TYPE_FULL = 1
LOG_TYPE_FIRST = 2
LOG_TYPE_MIDDLE = 3
LOG_TYPE_LAST = 4

# LevelDB write batch record types, see leveldb/db/dbformat.h
BATCH_HEADER_SIZE = 12
BATCH_TYPE_DELETION = 0
BATCH_TYPE_VALUE = 1

# LevelDB table constants, see leveldb/table/format.h
TABLE_FOOTER_SIZE = 48
TABLE_TRAILER_SIZE = 5  # one compression byte plus a four byte checksum
TABLE_MAGIC = (0xDB4775248B80FB57).to_bytes(8, "little")
TABLE_COMPRESSION_NONE = 0
TABLE_COMPRESSION_SNAPPY = 1

# V8 serialization tags, see v8/src/objects/value-serializer.cc
V8_TAG_ONE_BYTE_STRING = 0x22  # '"'
V8_TAG_UTF8_STRING = 0x53      # 'S'
V8_TAG_TWO_BYTE_STRING = 0x63  # 'c'
V8_TAG_INT32 = 0x49            # 'I'
V8_TAG_UINT32 = 0x55           # 'U'
V8_TAG_DOUBLE = 0x4E           # 'N'


def parse_encu(data):
    """Parse ENCU and return IV and AES-256-CBC encrypted email to compare against"""
    data = data.decode("utf-8")

    initialization_vector = None
    encrypted_email = None

    try:
        # Format: ![B64]|[B64]
        result = search(r"^!(.*)\|(.*)$", data)
        initialization_vector = result.group(1)
        encrypted_email = result.group(2)

        initialization_vector = b64decode(initialization_vector).hex()
        encrypted_email = b64decode(encrypted_email).hex()
    except:
        # B64 Only. This implies EBC, not CBC, mode and IV is found elsewhere, e.g., in database
        encrypted_email = b64decode(data).hex()

    return initialization_vector, encrypted_email


def open_file(file_name):
    """Open file and return contents"""
    with open(file_name, "rb") as file_handle:
        return file_handle.read()


def parse_vault(xml):
    """Parse Vault according to format: 4 bytes ASCII identifier, 4 bytes size, size bytes data"""
    magic_bytes = xml[:4].decode("utf-8")
    if magic_bytes != "LPAV":
        sys.exit(f"Expected LPAV in base 64 decoded XML, but found {magic_bytes}")

    offset = 0
    while offset < len(xml):
        identifier = xml[offset:offset + 4].decode("utf-8")
        offset = offset + 4
        size = int.from_bytes(xml[offset:offset + 4], byteorder='big')
        offset = offset + 4
        data = xml[offset:offset + size]

        if identifier == 'ENCU':
            initialization_vector, encrypted_email = parse_encu(data)
            return initialization_vector, encrypted_email

        offset = offset + size

    return None, None


def sqlite_parse_chromium(cur):
    """Chrome and Opera"""
    iterations = -1
    xml = ""
    try:
        res = cur.execute("SELECT data FROM LastPassData WHERE type='accts'")
        (xml,) = res.fetchone()
        result = search(r"^iterations=(\d+);(.*)$", xml)
        iterations = result.group(1)
        xml = result.group(2)
        xml = b64decode(xml)
    except:
        return None, None

    return iterations, xml


def sqlite_parse_firefox(cur):
    """Firefox"""
    iterations = -1
    encu = ""
    try:
        res = cur.execute("SELECT value FROM data WHERE key LIKE '%sch'")
        encu, = res.fetchone()
        encu = encu.decode("utf-8")
        encu = encu[encu.find("!"):]
        encu = encu[:encu.find("\n")]
        encu = bytes(encu, "utf-8")
        res = cur.execute("SELECT value FROM data WHERE key LIKE '%key_iter'")
        iterations, = res.fetchone()
        iterations = int(iterations)
    except:
        return None, None

    return iterations, encu


#
# LevelDB (Chrome IndexedDB) support
#


def _crc32c(data, table=[]):
    """CRC-32C (Castagnoli), the checksum LevelDB puts in front of every log record"""
    if not table:
        for index in range(256):
            crc = index
            for _ in range(8):
                crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
            table.append(crc)

    crc = 0xFFFFFFFF
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)

    return crc ^ 0xFFFFFFFF


def _mask_crc(crc):
    """LevelDB stores checksums rotated and offset so they never collide with real data"""
    return (((crc >> 15) | (crc << 17)) + 0xA282EAD8) & 0xFFFFFFFF


def _read_varint(buf, offset):
    """Read a protobuf style varint, return (value, new offset) or (None, offset) on truncation"""
    value = 0
    shift = 0
    while offset < len(buf):
        byte = buf[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            break

    return None, offset


def _read_length_prefixed(buf, offset):
    """Read a varint length followed by that many bytes"""
    length, offset = _read_varint(buf, offset)
    if length is None or offset + length > len(buf):
        return None, offset

    return buf[offset:offset + length], offset + length


def leveldb_log_records(data):
    """Yield the write batches stored in a LevelDB write ahead log file"""
    offset = 0
    pending = bytearray()

    while offset + LOG_HEADER_SIZE <= len(data):
        block_offset = offset % LOG_BLOCK_SIZE

        # The last few bytes of a block are zero padding, they never hold a header
        if LOG_BLOCK_SIZE - block_offset < LOG_HEADER_SIZE:
            offset += LOG_BLOCK_SIZE - block_offset
            continue

        crc, length, record_type = struct.unpack_from("<IHB", data, offset)

        if record_type == LOG_TYPE_ZERO or offset + LOG_HEADER_SIZE + length > len(data):
            offset += LOG_BLOCK_SIZE - block_offset
            pending.clear()
            continue

        payload = data[offset + LOG_HEADER_SIZE:offset + LOG_HEADER_SIZE + length]

        if _mask_crc(_crc32c(bytes([record_type]) + payload)) != crc:
            # Corrupt record, LevelDB itself drops the remainder of the block as well
            offset += LOG_BLOCK_SIZE - block_offset
            pending.clear()
            continue

        offset += LOG_HEADER_SIZE + length

        if record_type == LOG_TYPE_FULL:
            yield bytes(payload)
        elif record_type == LOG_TYPE_FIRST:
            pending = bytearray(payload)
        elif record_type == LOG_TYPE_MIDDLE:
            pending.extend(payload)
        elif record_type == LOG_TYPE_LAST:
            pending.extend(payload)
            yield bytes(pending)
            pending = bytearray()


def leveldb_batch_values(batch):
    """Yield the values of a LevelDB write batch, deletions carry no value"""
    if len(batch) < BATCH_HEADER_SIZE:
        return

    offset = BATCH_HEADER_SIZE
    while offset < len(batch):
        record_type = batch[offset]
        offset += 1

        if record_type not in (BATCH_TYPE_DELETION, BATCH_TYPE_VALUE):
            return

        key, offset = _read_length_prefixed(batch, offset)
        if key is None:
            return

        if record_type == BATCH_TYPE_DELETION:
            continue

        value, offset = _read_length_prefixed(batch, offset)
        if value is None:
            return

        yield value


def _v8_string_at(buf, offset):
    """Decode a V8 serialized string at offset, return None when there is no string there"""
    if offset >= len(buf):
        return None

    tag = buf[offset]
    length, offset = _read_varint(buf, offset + 1)
    if length is None or offset + length > len(buf):
        return None

    raw = buf[offset:offset + length]

    try:
        if tag == V8_TAG_ONE_BYTE_STRING:
            return raw.decode("latin-1")
        if tag == V8_TAG_UTF8_STRING:
            return raw.decode("utf-8")
        if tag == V8_TAG_TWO_BYTE_STRING:
            return raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None

    return None


def _v8_number_at(buf, offset):
    """Decode a V8 serialized number at offset, return None when there is no number there"""
    if offset >= len(buf):
        return None

    tag = buf[offset]

    if tag == V8_TAG_INT32:
        value, _ = _read_varint(buf, offset + 1)
        if value is None:
            return None
        # int32 values are zigzag encoded
        return (value >> 1) ^ -(value & 1)

    if tag == V8_TAG_UINT32:
        value, _ = _read_varint(buf, offset + 1)
        return value

    if tag == V8_TAG_DOUBLE:
        if offset + 9 > len(buf):
            return None
        return struct.unpack_from("<d", buf, offset + 1)[0]

    return None


def _field_offsets(buf, name):
    """Yield the offsets just past every occurrence of a field name, ASCII and UTF-16LE"""
    for encoded in (name.encode("ascii"), name.encode("utf-16-le")):
        start = 0
        while True:
            found = buf.find(encoded, start)
            if found < 0:
                break
            yield found + len(encoded)
            start = found + 1


def _decode_cbc_blob(iv_b64, ciphertext_b64):
    """Turn a !<IV>|<ciphertext> pair into hex, or return None when it is not a LastPass blob"""
    try:
        initialization_vector = b64decode(iv_b64, validate=True)
        ciphertext = b64decode(ciphertext_b64, validate=True)
    except Exception:
        return None

    if len(initialization_vector) != 16:
        return None

    if len(ciphertext) < 16 or len(ciphertext) % 16:
        return None

    # Only the first ciphertext block is needed, that is all the kernel compares against
    return initialization_vector.hex(), ciphertext[:16].hex()


def _cbc_blobs_in(buf, rejects=None):
    """Yield every (iv_hex, ciphertext_hex) LastPass blob found in a byte buffer"""
    for regex, strip in ((CBC_BLOB_RE, False), (CBC_BLOB_UTF16_RE, True)):
        for match in regex.finditer(buf):
            iv_b64, ciphertext_b64 = match.group(1), match.group(2)
            if strip:
                iv_b64 = iv_b64.replace(b"\x00", b"")
                ciphertext_b64 = ciphertext_b64.replace(b"\x00", b"")

            blob = _decode_cbc_blob(iv_b64, ciphertext_b64)
            if blob:
                yield blob
            elif rejects is not None:
                rejects.append((iv_b64[:24], ciphertext_b64[:24], _reject_reason(iv_b64, ciphertext_b64)))


def _reject_reason(iv_b64, ciphertext_b64):
    """Explain why a !<iv>|<ciphertext> candidate was not usable, for --debug"""
    try:
        initialization_vector = b64decode(iv_b64, validate=True)
    except Exception:
        return "iv is not base64"

    try:
        ciphertext = b64decode(ciphertext_b64, validate=True)
    except Exception:
        return "ciphertext is not base64"

    if len(initialization_vector) != 16:
        return f"iv is {len(initialization_vector)} bytes, not 16"

    if len(ciphertext) < 16:
        return f"ciphertext is {len(ciphertext)} bytes, under one block"

    return f"ciphertext is {len(ciphertext)} bytes, not a whole number of blocks"


def _vault_encu_blob(vault):
    """Walk the chunks of an LPAV vault and return the blob of its ENCU chunk"""
    offset = 0

    while offset + 8 <= len(vault):
        identifier = vault[offset:offset + 4]
        size = int.from_bytes(vault[offset + 4:offset + 8], "big")
        offset += 8

        if size > len(vault) - offset:
            return None

        if identifier == b"ENCU":
            # ENCU holds the account e-mail encrypted with the key derived from the password
            return next(_cbc_blobs_in(vault[offset:offset + size]), None)

        offset += size

    return None


def _find_vaults(buf):
    """Find LPAV vaults in a buffer, stored either as raw bytes or base64"""
    vaults = []

    for haystack in (buf, buf.replace(b"\x00", b"")):
        start = 0
        while True:
            found = haystack.find(b"LPAV", start)
            if found < 0:
                break
            vaults.append(haystack[found:])
            start = found + 1

        # base64 of "LPAV" starts with TFBBV, that is how the vault sits in the extension storage
        for match in re.finditer(rb"TFBBV[A-Za-z0-9+/]+={0,2}", haystack):
            encoded = match.group(0)
            try:
                decoded = b64decode(encoded + b"=" * (-len(encoded) % 4))
            except Exception:
                continue

            if decoded.startswith(b"LPAV"):
                vaults.append(decoded)

    return vaults


def leveldb_parse_vaults(buf):
    """Return the ENCU blob of every LPAV vault in a value, that is the account e-mail"""
    blobs = []

    for vault in _find_vaults(buf):
        blob = _vault_encu_blob(vault)
        if blob and blob not in blobs:
            blobs.append(blob)

    return blobs


def leveldb_parse_encrypted_usernames(buf, rejects=None):
    """Find the LastPass blobs of one IndexedDB value, anchored to the field name and not"""
    anchored = []

    for field in ENCRYPTED_USERNAME_FIELDS:
        for offset in _field_offsets(buf, field):
            # The field name is directly followed by its value, decode it the way V8 wrote it
            value = _v8_string_at(buf, offset)

            # JSON, UTF-16 or any other wrapping is covered by scanning the bytes that follow
            candidates = [buf[offset:offset + 4096]]
            if value:
                candidates.append(value.encode("latin-1", "ignore"))

            for candidate in candidates:
                for blob in _cbc_blobs_in(candidate, rejects):
                    if blob not in anchored:
                        anchored.append(blob)

    # The field name may be stored apart from its value, or spelled differently, so also take
    # every LastPass blob in the value. A vault holds one per secret, hence these stay separate.
    unanchored = []
    for blob in _cbc_blobs_in(buf, rejects):
        if blob not in anchored and blob not in unanchored:
            unanchored.append(blob)

    return anchored, unanchored


def leveldb_parse_iterations(buf):
    """Find the PBKDF2 iteration count of a single IndexedDB value"""
    # The extension stores the vault as "iterations=NNN;<base64>", same as the old SQLite row
    result = search(rb"iterations=(\d{1,7});", buf.replace(b"\x00", b""))
    if result:
        return int(result.group(1))

    for field in ITERATIONS_FIELDS:
        for offset in _field_offsets(buf, field):
            value = _v8_number_at(buf, offset)

            if value is None:
                text = _v8_string_at(buf, offset)
                if text is None:
                    # Fall back to whatever digits directly follow the field name
                    window = buf[offset:offset + 32].replace(b"\x00", b"")
                    result = search(rb"^[^0-9]{0,8}([0-9]{1,7})", window)
                    text = result.group(1).decode("ascii") if result else None

                try:
                    value = int(text)
                except (TypeError, ValueError):
                    continue

            value = int(value)

            if 1 <= value <= 1000000:
                return value

    return None


def _snappy_decompress(data):
    """Decompress a snappy block, LevelDB compresses its table blocks with it by default"""
    expected, offset = _read_varint(data, 0)
    if expected is None:
        return None

    out = bytearray()

    while offset < len(data):
        tag = data[offset]
        offset += 1

        if tag & 0x03 == 0:
            # Literal, the length is either packed in the tag or in the bytes that follow
            length = tag >> 2
            if length >= 60:
                extra = length - 59
                if offset + extra > len(data):
                    return None
                length = int.from_bytes(data[offset:offset + extra], "little")
                offset += extra
            length += 1

            if offset + length > len(data):
                return None

            out += data[offset:offset + length]
            offset += length
            continue

        # Copy, back reference into what has been emitted so far
        if tag & 0x03 == 1:
            if offset >= len(data):
                return None
            length = 4 + ((tag >> 2) & 0x07)
            copy_offset = ((tag >> 5) << 8) | data[offset]
            offset += 1
        elif tag & 0x03 == 2:
            if offset + 2 > len(data):
                return None
            length = (tag >> 2) + 1
            copy_offset = int.from_bytes(data[offset:offset + 2], "little")
            offset += 2
        else:
            if offset + 4 > len(data):
                return None
            length = (tag >> 2) + 1
            copy_offset = int.from_bytes(data[offset:offset + 4], "little")
            offset += 4

        if copy_offset == 0 or copy_offset > len(out):
            return None

        start = len(out) - copy_offset
        for index in range(length):
            out.append(out[start + index])

    if len(out) != expected:
        return None

    return bytes(out)


def _leveldb_read_block(data, offset, size):
    """Read one table block and decompress it, the byte after the block names the compression"""
    if offset + size + TABLE_TRAILER_SIZE > len(data):
        return None

    block = data[offset:offset + size]
    compression = data[offset + size]

    if compression == TABLE_COMPRESSION_NONE:
        return block

    if compression == TABLE_COMPRESSION_SNAPPY:
        return _snappy_decompress(block)

    # zstd and zlib are possible in newer forks, neither is what Chrome writes
    return None


def _leveldb_block_handles(block):
    """Yield the (offset, size) block handles stored as the values of an index block"""
    if len(block) < 4:
        return

    # The block ends with a restart array, its length is the last four bytes
    restart_count = int.from_bytes(block[-4:], "little")
    end = len(block) - 4 - (restart_count * 4)
    if end <= 0:
        return

    offset = 0
    while offset < end:
        shared, offset = _read_varint(block, offset)
        non_shared, offset = _read_varint(block, offset)
        value_length, offset = _read_varint(block, offset)

        if shared is None or non_shared is None or value_length is None:
            return
        if offset + non_shared + value_length > len(block):
            return

        offset += non_shared
        value = block[offset:offset + value_length]
        offset += value_length

        block_offset, handle_offset = _read_varint(value, 0)
        block_size, _ = _read_varint(value, handle_offset)

        if block_offset is not None and block_size is not None:
            yield block_offset, block_size


def leveldb_table_blocks(data):
    """Yield the decompressed data blocks of a LevelDB table (.ldb/.sst) file"""
    if len(data) < TABLE_FOOTER_SIZE:
        return

    footer = data[-TABLE_FOOTER_SIZE:]

    if footer[-8:] != TABLE_MAGIC:
        return

    # The footer holds the metaindex handle followed by the index handle
    _, offset = _read_varint(footer, 0)
    _, offset = _read_varint(footer, offset)
    index_offset, offset = _read_varint(footer, offset)
    index_size, _ = _read_varint(footer, offset)

    if index_offset is None or index_size is None:
        return

    index_block = _leveldb_read_block(data, index_offset, index_size)
    if index_block is None:
        return

    for block_offset, block_size in _leveldb_block_handles(index_block):
        block = _leveldb_read_block(data, block_offset, block_size)
        if block:
            yield block


def blob_directory(path):
    """Return the .blob directory Chrome keeps next to a .leveldb directory, if there is one"""
    base = os.path.normpath(path)

    # Values too large to sit in LevelDB are written to <origin>.indexeddb.blob instead
    if not base.endswith(".leveldb"):
        return None

    sibling = base[:-len(".leveldb")] + ".blob"

    return sibling if os.path.isdir(sibling) else None


def leveldb_files(path):
    """Return the files to inspect, a single file or every file under a store directory"""
    if os.path.isfile(path):
        return [path]

    roots = [path]

    sibling = blob_directory(path)
    if sibling:
        roots.append(sibling)

    entries = []
    for root in roots:
        # Blob directories nest the files below a database id, so walk the whole tree
        for directory, _, names in os.walk(root):
            for name in sorted(names):
                # LOCK, LOG and CURRENT never hold vault data
                if name in ("LOCK", "LOG", "LOG.old", "CURRENT"):
                    continue
                entries.append(os.path.join(directory, name))

    return entries


def leveldb_values(data):
    """Return the stored values of a LevelDB file, and how they were recovered"""
    # A write ahead log, every value comes back exactly as it was written
    batches = list(leveldb_log_records(data))
    values = [value for batch in batches for value in leveldb_batch_values(batch)]
    if values:
        return values, f"log, {len(batches)} batches"

    # A compacted table, the blocks have to be decompressed before anything is readable
    blocks = list(leveldb_table_blocks(data))
    if blocks:
        return blocks, f"table, {len(blocks)} blocks"

    # An externally stored value, Chrome may write the whole blob file as one snappy stream
    decompressed = _snappy_decompress(data)
    if decompressed:
        return [decompressed, data], "snappy blob"

    # Nothing structural to go on, fall back to scanning the raw bytes
    return [data], "raw scan"


def _display_path(root, file_name):
    """Shorten a path for the debug listing, relative to the store when possible"""
    parent = os.path.dirname(os.path.normpath(root))
    try:
        return os.path.relpath(file_name, parent)
    except ValueError:
        return file_name


def leveldb_parse(path, debug=False):
    """Parse a Chrome IndexedDB LevelDB store, return (iterations, [(iv_hex, ciphertext_hex)])"""
    blobs = []
    others = []
    iterations = None

    for file_name in leveldb_files(path):
        data = open_file(file_name)
        values, how = leveldb_values(data)

        found = []
        loose = []
        rejects = [] if debug else None

        for value in values:
            anchored, unanchored = leveldb_parse_encrypted_usernames(value, rejects)

            # An LPAV vault names its chunks, so its ENCU chunk is the account e-mail for certain
            anchored = leveldb_parse_vaults(value) + anchored

            for blob in anchored:
                if blob not in found:
                    found.append(blob)
            for blob in unanchored:
                if blob not in loose:
                    loose.append(blob)

            if iterations is None:
                iterations = leveldb_parse_iterations(value)

        # found counts what this file holds, the same vault is usually in several of them
        blobs.extend(blob for blob in found if blob not in blobs)
        others.extend(blob for blob in loose if blob not in others)

        if debug:
            names = sorted({
                field
                for field in ENCRYPTED_USERNAME_FIELDS + ITERATIONS_FIELDS
                for value in values
                if next(_field_offsets(value, field), None) is not None
            })
            print(
                f"{_display_path(path, file_name):<40} {len(data):>9} bytes  "
                f"{how:<20} fields={','.join(names) or '-':<32} "
                f"named={len(found)} loose={len(loose)}",
                file=sys.stderr,
            )

            seen = []
            for reject in rejects:
                if reject not in seen:
                    seen.append(reject)

            for iv_b64, ciphertext_b64, reason in seen[:3]:
                print(
                    f"    rejected !{iv_b64.decode('latin-1')}|"
                    f"{ciphertext_b64.decode('latin-1')}... {reason}",
                    file=sys.stderr,
                )

    return iterations, blobs, others


def main():
    """Entry point"""
    argv = [arg for arg in sys.argv[1:] if not arg.startswith("--")]
    options = [arg for arg in sys.argv[1:] if arg.startswith("--")]

    forced_iterations = None
    debug = False
    for option in options:
        if option.startswith("--iterations="):
            forced_iterations = int(option.split("=", 1)[1])
        elif option == "--debug":
            debug = True
        else:
            sys.exit(f"Unknown option {option}")

    usage = (
        f"Usage: {sys.argv[0]} <xml, sqlite or LevelDB file/directory> <username (email)> [--iterations=N] [--debug]"
    )

    if not argv:
        sys.exit(usage)

    if len(argv) < 2:
        # The e-mail is not in the vault in plain text, it is both the PBKDF2 salt and the
        # plaintext hashcat encrypts to compare against, so it has to be named on the command line
        sys.exit(
            f"Missing the account e-mail, it is the salt of the hash and cannot be read from "
            f"{argv[0]}\n{usage}\nFor example: {sys.argv[0]} {argv[0]} you@example.com"
        )

    file_name = argv[0]
    if not os.path.exists(file_name):
        sys.exit(f"File {file_name} does not exist")

    # Output will contain the following fields (in order), colon separated
    encrypted_email = ""
    iterations = -1
    email = argv[1].lower()
    initialization_vector = ""

    magic_bytes = ""
    if os.path.isfile(file_name):
        magic_bytes = open_file(file_name)[:5].decode("utf-8", "replace")

    if magic_bytes == "LPB64":
        # Android App
        iterations = DEFAULT_ITERATIONS
        xml = b64decode(open_file(file_name)[5:])
        initialization_vector, encrypted_email = parse_vault(xml)

    elif magic_bytes == "SQLit":
        # Browser Extension, older SQLite based storage
        con = sqlite3.connect(file_name)
        cur = con.cursor()

        # First try Chromium based browsers
        iterations, xml = sqlite_parse_chromium(cur)
        if iterations and xml:
            initialization_vector, encrypted_email = parse_vault(xml)

        # Then try Firefox
        if not encrypted_email or not iterations or not initialization_vector:
            iterations, encu = sqlite_parse_firefox(cur)
            if encu:
                initialization_vector, encrypted_email = parse_encu(encu)

        # Finally give up
        if not encrypted_email or not iterations or not initialization_vector:
            sys.exit("Unexpected behaviour in SQLite database parsing")

        con.close()
    else:
        # Browser Extension, Chrome IndexedDB (LevelDB) storage
        iterations, blobs, others = leveldb_parse(file_name, debug)

        if not blobs and others:
            # Nothing carried the encryptedUsername name, fall back to every LastPass blob found
            print(
                f"Warning: found no encryptedUsername field, falling back to all {len(others)} "
                "encrypted values found. A vault holds one per secret, so most of these are "
                "passwords and notes, not the account e-mail. Try each line against -m 6800, "
                "only the account e-mail one can crack",
                file=sys.stderr,
            )
            blobs = others

        if not blobs:
            sys.exit(
                f"Found no usable LastPass encrypted value in {file_name}\n"
                "Expected an LPB64 file, a SQLite database or a LevelDB store. Re-run with "
                "--debug to see which files were read, which fields they hold and why any "
                "!<iv>|<ciphertext> candidate was rejected\n"
                "Note the e-mail argument plays no part in this, it is only copied into the output"
            )

        if forced_iterations is None and iterations is None:
            print(
                f"Warning: no iterations field found, assuming {DEFAULT_ITERATIONS}",
                file=sys.stderr,
            )

        iterations = forced_iterations or iterations or DEFAULT_ITERATIONS

        for initialization_vector, encrypted_email in blobs:
            print(f"{encrypted_email}:{iterations}:{email}:{initialization_vector}")

        return

    if forced_iterations is not None:
        iterations = forced_iterations

    print(f"{encrypted_email}:{iterations}:{email}:{initialization_vector}")


if __name__ == "__main__":
    main()
