[![Manual Release (Go)](https://github.com/DJStompZone/PackUnPacker/actions/workflows/manual-release-go.yml/badge.svg)](https://github.com/DJStompZone/PackUnPacker/actions/workflows/manual-release-go.yml)

Join a partnered/Third party server, and decrypt their protected assets.

pack.mcpack (ZIP bytes)
  -> contents.json.enc [optional 256-byte header if magic 0x9BCFB9FC]
    -> keyCandidates{ raw|case|+UUID|hex/base64/base32 decodes|PBKDF2 salts }
      -> FIRST key producing valid JSON via AES-256-CFB8 (IV=key[:16])
        -> contents.json (plain manifest)
          -> entries: content[i] = { path, key? }
            -> for each entry:
                 if key (32 chars): asset.enc --AES-256-CFB8(key, key[:16])--> asset.plain
                 else: asset.plain (direct)
                   -> write packs/<base>_decrypted/{ contents.json + assets }
