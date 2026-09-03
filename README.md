Ruminant is a recursive metadata extraction and file dissection tool.

# What does it do?
Ruminant takes a file as an input and spits out a huge json object that contains all the (meta)data it extracted from the file. This is done recursively, e.g. by running ruminant again on each file inside a ZIP file or on the thumbnail inside a JPEG file.

# Why the name?
To quote Wikipedia: Ruminants are herbivorous grazing or browsing artiodactyls [...]. The process of rechewing the cud to further break down plant matter and stimulate digestion is called rumination. The word "ruminant" comes from the Latin ruminare, which means "to chew over again".

This tool behaves similarly as extracted blobs themselves can be "chewed over again" (the main entrypoint is literally called chew()) in order to recursively extract metadata.

# What can it process?
Ruminant is still in early alpha but it can already process the following file types:
* Android AVB vbmeta partitions
* Android boot images
* FLAC
* ID3v2 (e.g. wrapping MP3 files)
* MP3
* MIDI
* GZip
* BZip2
* Zstd
* Zlib
* XZ
* ZIP
  * embedded Android APK signatures
  * ZipCrypto encryption, no AES though
* RIFF
    * WebP
    * WAV
    * AVI
    * DjVu
* Tar
* Ar
* CPIO
* HTTP framed streams like MJPEG
* Java Jmod
* UF2
* DVD MPEG sequences
* Grub 2 modules
* Android backups
  * no encryption yet
* Cab
* IWA
* PcapNG
  * IPv4/IPv6/LLDP/ARP
  * UDP/TCP/ICMP/IGMP/ICMPv6
  * DNS
      * A/OPT/SOA/AAAA/MX/TXT/CAA/DNSKEY/RRSIG/HTTPS/NS/SSHFP/OPENPGPKEY/SRV/DS/NSEC3
* NCSD (Nintendo 3DS)
* NCCH (Nintendo 3DS)
* SMDH (Nintendo 3DS)
* DARC (Nintendo 3DS)
* DER (binary)
* PEM
* PGP (binary or armored)
* KeePass KDBX
  * including AES and ChaCha20 decryption, no Twofish though
* Age
* LUKS 1/2
  * encryption for LUKS2 when used with aes-xts-plain64 and supplied MK
* SSH signatures
* EFI signature lists
* PDF
* WASM
* Java classes
  * including full disassembly
* ELF
* PE/EXE/EFI
* SPIR-V shaders
* Python bytecode
  * no disassembly due to unstable nature of bytecode
* Intel microcode
  * including signature extraction
* a.out
* MBR/GPT partition tables
* BTRFS send streams
* TrueType fonts
* Adobe Photoshop IRB chunks
* ICC profiles
* JPEG
* PNG
* TIFF
  * EXIF metadata is just a TIFF file
* GIF
* Google HDR+ MakerNotes
  * I reverse engineered that btw :D
* PSD (Adobe Photoshop)
* DICOM
* OpenEXR
* ICO
* Qoi
* BitTorrent files
* Sqlite3 databases
* Minecraft NBT
* Minecraft MCA chunk regions
* Git related files (blob, tree, commit)
* OpenTimestamps proof files
* Java serialization data
* Safetensors models
* GGUF models
* Apple binary property lists
  * text based ones are just XML
* OpenStreetMap protobufs
* STL models
* AppleDouble
* Microsoft printer settings
  * you may find them in XLSX files
* Mindustry schematics
* UTF-8 text files
  * including detection and parsing for base64, JSON and XML
* Empty files (duh)
* Zero filled files (also duh)
* ISOBMFF
  * MP4/MOV/HEIC/HEIF/AVIF/JPEG2000
* EBML/Matroska/MKV/WebM
* Ogg/Ogv
* MPEG-TS
* ASF/WMA/WMV
* Duck IVF
* Dirac data units
* JVT-NAL H.264

## Video codecs
Ruminant can extract and parse data units of specific codecs from specific containers.

### Legend
❌: not yet supported

🚧: partially supported

✅: fully supported (or at least as much as I want it to be)

empty means the container doesn't support it

|Codec|MP4|MKV|MPEG-TS|Duck IVF|HEIF|
|-|-|-|-|-|-|
|MPEG-2|🚧|🚧|🚧|||
|H.264|✅|✅|✅||✅|
|H.265|🚧|🚧|🚧||🚧|
|H.266|🚧|🚧|❌|||
|AV1|✅|✅||✅|✅|
|AV2|🚧|🚧||❌|❌|
|Dirac|✅|✅||||
|ProRes||✅||||
|Vorbis|🚧|🚧||||
|Theora||🚧||||
|AC-3|✅|✅|✅|||
|MP2|✅|✅|✅|||
|MP3|✅|✅|✅|||
|AAC|❌|✅|❌|||
|FLAC|🚧|🚧||||
|Opus|🚧|🚧||||
|TX3G|✅|||||
|METT|✅|||||
|DVBSUB||✅|✅|||
|Teletext|||✅|||

# How do I install it?
Run `pip3 install ruminant\[full\]` if you want C acceleration or `pip3 install ruminant` if you want pure Python.

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
Adding `-p <ID> <VALUE>` adds a parameter with a value. This can for example be used to specify decoding ranges or cryptographic keys.
One example would be to run ruminant on an encrypted ZIP file which contains the following JSON object:
```"key": {
  "name": "47fafe9b1ce795e5ece32c5e",
  "found": false
}
```
The key can then be specified by adding `-p 47fafe9b1ce795e5ece32c5e foobar` to the command.
Adding `--slim` removes all unnecessary whitespace from the output.
Adding `--shallow` prevents recursive parsing.
Running ruminant on a directory processes all files in the directory. Adding `--filename-regex <REGEX>` makes it only process files that match the regex.
Adding `--print-modules` prints all registered modules and exits.
Adding `--self-test` runs a test suite and exits.
Adding `--version` prints the version and exits.

# Ruminant can't parse xyz
Feel free to send me a sample so I can add a parser for it :)
