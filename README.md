Ruminant is a recursive metadata extraction and file dissection tool.

# What does it do?
Ruminant takes a file as an input and spits out a huge json object that contains all the metadata it extracted from the file. This is done recursively, e.g. by running ruminant again on each file inside a zip file.

# Why the name?
To quote Wikipedia: Ruminants are herbivorous grazing or browsing artiodactyls [...]. The process of rechewing the cud to further break down plant matter and stimulate digestion is called rumination. The word "ruminant" comes from the Latin ruminare, which means "to chew over again".

This tool behaves similarly as extracted blobs themselves can be "chewed over again" (the main entrypoint is literally called chew()) in order to recursively extract metadata.

# What can it process?
Ruminant is still in early alpha but it can already process the following file types:
* ZIP files
  * APK signatures
  * Java jmod modules
  * encrypted files
* PDF files
  * I hate Adobe
* JPEG files
  * EXIF metadata
  * XMP metadata
  * ICC profiles
  * IPTC metadata
  * Adobe-specific metadata in APP14
  * MPF APP2 segments
* PNG files
  * EXIF metadata
* TIFF files
  * EXIF metadata (EXIF metadata is literally stored in a TIFF file)
  * DNG files
* ISO files
  * MP4 files
  * AVIF files
  * HEIF/HEIC stuff
  * XMP metadata
  * AVC1 x264 banners
  * all of the DRM stuff that Netflix puts in their streams
    * CENC
    * PlayReady
    * Widevine
  * SEFT metadata
* ICC profiles
  * EP0763801A2 extension
* TrueType fonts
* RIFF files
  * WebP
  * WAV
* GIF files
* EBML files
  * Matroska
    * WebM
* Ogg files
  * Opus metadata
  * Theora metadata
  * Vorbis metadata
* FLAC files
* DER data
  * X509 certificates
  * PEM files
* GZIP streams
* BZIP2 streams
* TAR files
  * USTAR to be precise
* PGP stuff
* ID3v2 tags
* MPEG-TS
* MakerNotes
  * Fuji
  * Sony
  * Google HDR+
* PSD files
* KDBX files
* JPEG2000 files
* C2PA CAI JUMBF metadata
* WASM files
* Torrent files
* Sqlite3 database files
* DICOM files
* ASF files
  * WMA files
  * WMV files
* age encrypted files
  * tlock extensions
* LUKS headers
* Java class files
* ELF files
  * .comment sections
  * .interp sections
  * .note sections
  * some PS3/PS4 SELF stuff
* PE files
  * Authenticode signatures
  * GRUB modules in EFI files
* Minecraft NBT files
  * region files
* SPIR-V binaries
* Ar archives
* Cpio archives
* Zstd files
* SSH signatures
* Git object files
* Intel microcode files
  * including public key detection and signature extraction
* EXR/OpenEXR files
* Android vbmeta partitions
* PDP-11 a.out files
* OpenTimestamps proof files
* xz files
* UF2 files
* Android adb backup files
* Java object serialization data
* Safetensors files
* Microsoft cabinet files
* btrfs stream files
* Duck IVF video files
* Apple binary plist files
  * the text ones are just already supported XML files
* GGUF files
* pcapng files
* OpenStreetMap protobuf files
* ICO files
* MP3 files
  * ID3v1/ID3v1.1 footer
* 3DS files
  * NCSD files
  * NCCH files
  * SMDH files
  * DARC files
* MIDI files
* binary STL files
* EFI signature lists (like db or dbx)
* qoi image files
* AppleDouble files

# How do I install it?
Run `pip3 install ruminant`.
Alternatively, you can also run `python3 -m build` in the source tree, followed by `pip3 install dist/*.whl`.

# How do I use it?
The most basic usage would be `ruminant <file>` in order to process the file and output all metadata.

Each time a blob is passed to chew(), it gets assigned a new unique ID that is stored in the "blob-id" field in its JSON object.
These blobs can be extracted with `ruminant <file> --extract <ID> <file name>`. The `--extract` option can also be shortened to `-e` and can be repeated multiple times.

Not specifying a file means that it reads from `-`, which is the standard input. You can also explicitly pass `-` as the file.

The `--walk` or `-w` option enables a binwalk-like mode where ruminant tries to parse a file and increments the start offset by one until it can correctly parse something. This is done until the end of the file.

This is a valid complex command: `ruminant -e 2 foo.jpeg - --extract 5 bar.bin -e 0 all.zip`

(Yes, you could abuse ruminant to copy files by running `function cp() { ruminant --extract 0 $2 $1 }` in bash and then using the function as `cp`.)

You can also specify `--extract-all` in order to extract all blobs to the "blobs" directory.
Specifying a directory as the file makes ruminant walk that directory recursively. Adding `--progress` shows a progress bar (this requires tqdm). Adding `--progress-names` adds file names to the progress bar.
Specifying `--url` makes ruminant treat the file name as a URL and makes it try to fetch the file from it. It uses the user agent of a recent Chrome to not be blocked.
Adding `--strip-url` makes ruminant change some parts of known URLs to preserve metadata. It can, for example, detect that a file is being hosted by Wordpress based on the "/wp-content/" start of the path and can then remove the "-<width>x<height>" part of the file name to preserve its original size and avoid reencoding of the file.
The user agent can be overridden by setting the `RUMINANT_USER_AGENT` environment variable with the desired agent.

# Ruminant can't parse xyz
Feel free to send me a sample so I can add a parser for it :)
