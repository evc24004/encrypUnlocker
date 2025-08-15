package main

import (
    "archive/zip"
    "bytes"
    "crypto/aes"
    "crypto/sha256"
    "encoding/base32"
    "encoding/base64"
    "io"
    "fmt"
    "net"
    "os"
    "path/filepath"
    "compress/flate"
    stdjson "encoding/json"
    "slices"
    "golang.org/x/crypto/pbkdf2"
    "strings"
    "time"

    "github.com/go-jose/go-jose/v4/json"
    "github.com/sandertv/gophertunnel/minecraft"
    "github.com/sandertv/gophertunnel/minecraft/auth"
    "github.com/sandertv/gophertunnel/minecraft/protocol"
    "github.com/sandertv/gophertunnel/minecraft/protocol/packet"
    "golang.org/x/oauth2"
)

type ResourcePack struct {
    UUID        string
    Size        uint64
    Data        []byte
    ChunkCount  uint32
    Downloaded  uint32
    BytesFilled uint64
}

var (
    resourcePacks  = make(map[string]*ResourcePack)
    packsDir       = "packs"
    contentKeys    = make(map[string]string)
    expectedPacks  = make(map[string]struct{})
    completedPacks = make(map[string]struct{})
    conn           *minecraft.Conn
)

func main() {
    if err := os.MkdirAll(packsDir, 0755); err != nil {
        fmt.Printf("❌ Failed to create packs directory: %v\n", err)
        return
    }
    
    fmt.Println("🌐 Connecting to Galaxite Network...")
    
    var err error
    conn, err = minecraft.Dialer{
        TokenSource: tokenSource(),
        PacketFunc: func(header packet.Header, payload []byte, src, dst net.Addr) {
            pool := packet.NewServerPool()
            pkFunc, ok := pool[header.PacketID]
            if !ok {
                return
            }

            pkt := pkFunc()
            reader := bytes.NewReader(slices.Clone(payload))
            func() {
                defer func() { recover() }()
                pkt.Marshal(protocol.NewReader(reader, 0, true))
            }()

            handleResourcePackPacket(pkt)
        },
        DisconnectOnInvalidPackets: false,
        DisconnectOnUnknownPackets: false,
    }.DialTimeout("raknet", "play.galaxite.net:19132", time.Minute)
    
    if err != nil {
        fmt.Printf("❌ Connection failed: %v\n", err)
        return
    }
    defer conn.Close()
    
    fmt.Println("✅ Connected! Spawning...")

    if err = conn.DoSpawn(); err != nil {
        fmt.Printf("❌ Spawn failed: %v\n", err)
        return
    }
    
    fmt.Println("📦 Monitoring for resource packs...")

    for {
        _, err = conn.ReadPacket()
        if err != nil {
            fmt.Printf("❌ Connection lost: %v\n", err)
            break
        }
    }
}

func handleResourcePackPacket(pkt packet.Packet) {
    switch p := pkt.(type) {
    case *packet.ResourcePacksInfo:
        handleResourcePacksInfo(p)
    case *packet.ResourcePackDataInfo:
        handleResourcePackDataInfo(p)
    case *packet.ResourcePackChunkData:
        handleResourcePackChunkData(p)
    }
}

func handleResourcePacksInfo(pkt *packet.ResourcePacksInfo) {
    fmt.Printf("📋 Found %d resource pack(s)\n", len(pkt.TexturePacks))
    
    var packList []string
    for _, pack := range pkt.TexturePacks {
        uuid := pack.UUID.String()
        baseUUID := strings.Split(uuid, "_")[0]
        expectedPacks[baseUUID] = struct{}{}
        
        if pack.ContentKey != "" {
            contentKeys[baseUUID] = pack.ContentKey
            fmt.Printf("🔐 %s: Encrypted\n", baseUUID[:8])
        } else {
            fmt.Printf("📦 %s: Unencrypted\n", baseUUID[:8])
        }
        
        packList = append(packList, uuid+"_"+pack.Version)
    }

    if conn != nil {
        _ = conn.WritePacket(&packet.ResourcePackClientResponse{
            Response: packet.PackResponseSendPacks, 
            PacksToDownload: packList,
        })
        
        go func() {
            time.Sleep(150 * time.Millisecond)
            _ = conn.WritePacket(&packet.ResourcePackClientResponse{
                Response: packet.PackResponseAllPacksDownloaded,
            })
        }()
    }
}

func handleResourcePackDataInfo(pkt *packet.ResourcePackDataInfo) {
    uuid := pkt.UUID
    baseUUID := strings.Split(uuid, "_")[0]
    
    resourcePacks[uuid] = &ResourcePack{
        UUID:       uuid,
        Size:       pkt.Size,
        Data:       make([]byte, pkt.Size),
        ChunkCount: pkt.ChunkCount,
    }
    
    fmt.Printf("⬇️  %s: Starting download (%.1f MB)\n", 
        baseUUID[:8], 
        float64(pkt.Size)/(1024*1024))
}

func handleResourcePackChunkData(pkt *packet.ResourcePackChunkData) {
    uuid := pkt.UUID
    rp, exists := resourcePacks[uuid]
    if !exists {
        return
    }
    
    offset := pkt.DataOffset
    if offset+uint64(len(pkt.Data)) <= rp.Size {
        copy(rp.Data[offset:], pkt.Data)
        rp.Downloaded++
        rp.BytesFilled += uint64(len(pkt.Data))

        progress := 100.0
        if rp.ChunkCount > 0 {
            progress = float64(rp.Downloaded) / float64(rp.ChunkCount) * 100
        } else if rp.Size > 0 {
            progress = float64(rp.BytesFilled) / float64(rp.Size) * 100
        }
        if progress > 100 { 
            progress = 100 
        }
        
        fmt.Printf("⬇️  %s: %.1f%% (%d/%d chunks)\n", 
            strings.Split(uuid, "_")[0][:8], 
            progress, 
            rp.Downloaded, 
            rp.ChunkCount)

        // Check completion
        if (rp.ChunkCount > 0 && rp.Downloaded >= rp.ChunkCount) || 
           (rp.Size > 0 && rp.BytesFilled >= rp.Size) {
            processCompletedPack(rp)
        }
    }
}

func processCompletedPack(rp *ResourcePack) {
    baseUUID := strings.Split(rp.UUID, "_")[0]
    
    if _, encrypted := contentKeys[baseUUID]; encrypted {
        decryptResourcePack(rp)
    } else {
        saveRawPack(rp)
    }
    
    delete(resourcePacks, rp.UUID)
    markCompleted(baseUUID)
}

func saveRawPack(rp *ResourcePack) {
    baseUUID := strings.Split(rp.UUID, "_")[0]
    filename := fmt.Sprintf("%s.mcpack", baseUUID[:8])
    path := filepath.Join(packsDir, filename)
    
    if err := os.WriteFile(path, rp.Data, 0644); err != nil {
        fmt.Printf("❌ Failed to save %s: %v\n", filename, err)
        return
    }
    
    fmt.Printf("💾 Saved: %s (%.1f MB)\n", 
        filename, 
        float64(len(rp.Data))/(1024*1024))
}

func decryptResourcePack(rp *ResourcePack) {
    baseUUID := strings.Split(rp.UUID, "_")[0]
    contentKey := contentKeys[baseUUID]
    
    if len(contentKey) != 32 {
        fmt.Printf("❌ Invalid content key for %s\n", baseUUID[:8])
        return
    }
    
    fmt.Printf("🔓 Decrypting %s...\n", baseUUID[:8])
    
    // Extract files from pack
    allFiles := extractFiles(rp.Data)
    if len(allFiles) == 0 {
        fmt.Printf("❌ No files found in %s\n", baseUUID[:8])
        return
    }
    
    // Find and decrypt contents.json
    contentsData := findContentsFile(allFiles)
    if contentsData == nil {
        fmt.Printf("❌ No contents.json found in %s\n", baseUUID[:8])
        return
    }
    
    decryptedContents := tryDecryptContents(contentsData, contentKey, baseUUID)
    if decryptedContents == nil {
        fmt.Printf("❌ Failed to decrypt %s\n", baseUUID[:8])
        return
    }
    
    // Parse contents.json
    var contents struct {
        Content []struct {
            Path string `json:"path"`
            Key  string `json:"key"`
        } `json:"content"`
    }
    
    if err := stdjson.Unmarshal(decryptedContents, &contents); err != nil {
        fmt.Printf("❌ Invalid contents.json for %s\n", baseUUID[:8])
        return
    }
    
    // Create output directory and extract files
    outDir := filepath.Join(packsDir, fmt.Sprintf("%s_decrypted", baseUUID[:8]))
    if err := os.MkdirAll(outDir, 0755); err != nil {
        fmt.Printf("❌ Failed to create directory for %s\n", baseUUID[:8])
        return
    }
    
    extracted := extractAndDecryptFiles(contents.Content, allFiles, outDir)
    
    // Save decrypted contents.json
    os.WriteFile(filepath.Join(outDir, "contents.json"), decryptedContents, 0644)
    
    fmt.Printf("✅ Extracted %s: %d files\n", baseUUID[:8], extracted+1)
}

func extractFiles(data []byte) map[string][]byte {
    files := make(map[string][]byte)
    
    // Try standard ZIP first
    if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
        for _, f := range zr.File {
            if rc, err := f.Open(); err == nil {
                if fileData, err := io.ReadAll(rc); err == nil {
                    files[f.Name] = fileData
                }
                rc.Close()
            }
        }
    } else {
        // Try local ZIP headers
        _, files = scanLocalZipEntries(data)
    }
    
    return files
}

func findContentsFile(files map[string][]byte) []byte {
    for name, data := range files {
        lowerName := strings.ToLower(name)
        if lowerName == "contents.json" || 
           lowerName == "content.json" || 
           strings.Contains(lowerName, "contents") {
            return data
        }
    }
    return nil
}

func tryDecryptContents(data []byte, contentKey, baseUUID string) []byte {
    keys := generateKeys(contentKey, baseUUID)
    
    // Handle encryption header
    payload := data
    if validateHeader(data) && len(data) > 256 {
        payload = data[256:]
    }
    
    // Try each key with CFB8 mode
    for _, key := range keys {
        decrypted := decryptCFB8(key, key[:16], payload)
        decrypted = bytes.TrimRight(decrypted, "\x00")
        decrypted = normalizeLineEndings(decrypted)
        
        if stdjson.Valid(decrypted) && bytes.Contains(decrypted, []byte("\"content\"")) {
            return decrypted
        }
    }
    
    return nil
}

func extractAndDecryptFiles(contentList []struct{Path string `json:"path"`; Key string `json:"key"`}, allFiles map[string][]byte, outDir string) int {
    extracted := 0
    
    for _, entry := range contentList {
        if strings.HasSuffix(entry.Path, "/") {
            os.MkdirAll(filepath.Join(outDir, entry.Path), 0755)
            continue
        }
        
        fileData, exists := allFiles[entry.Path]
        if !exists {
            continue
        }
        
        // Decrypt if encrypted
        if entry.Key != "" && len(entry.Key) == 32 {
            keyBytes := []byte(entry.Key)
            fileData = decryptCFB8(keyBytes, keyBytes[:16], fileData)
        }
        
        outPath := filepath.Join(outDir, entry.Path)
        if err := os.MkdirAll(filepath.Dir(outPath), 0755); err == nil {
            if err := os.WriteFile(outPath, fileData, 0644); err == nil {
                extracted++
            }
        }
    }
    
    return extracted
}

func markCompleted(baseUUID string) {
    if _, expected := expectedPacks[baseUUID]; expected {
        completedPacks[baseUUID] = struct{}{}
        if len(completedPacks) == len(expectedPacks) {
            if conn != nil {
                _ = conn.WritePacket(&packet.ResourcePackClientResponse{
                    Response: packet.PackResponseCompleted,
                })
            }
            fmt.Println("✅ All packs processed!")
            time.AfterFunc(500*time.Millisecond, func() { os.Exit(0) })
        }
    }
}

func tokenSource() oauth2.TokenSource {
    token := new(oauth2.Token)
    if tokenData, err := os.ReadFile("token.tok"); err == nil {
        _ = json.Unmarshal(tokenData, token)
    } else {
        fmt.Println("🔐 Authentication required...")
        if newToken, err := auth.RequestLiveToken(); err == nil {
            token = newToken
        } else {
            fmt.Printf("❌ Authentication failed: %v\n", err)
            os.Exit(1)
        }
    }
    
    src := auth.RefreshTokenSource(token)
    if _, err := src.Token(); err != nil {
        fmt.Println("🔐 Re-authentication required...")
        if newToken, err := auth.RequestLiveToken(); err == nil {
            token = newToken
            src = auth.RefreshTokenSource(token)
        } else {
            fmt.Printf("❌ Re-authentication failed: %v\n", err)
            os.Exit(1)
        }
    }
    
    if tok, _ := src.Token(); tok != nil {
        if b, _ := json.Marshal(tok); b != nil {
            _ = os.WriteFile("token.tok", b, 0644)
        }
    }
    
    return src
}

// Core decryption functions
func validateHeader(data []byte) bool {
    if len(data) < 256 {
        return false
    }
    magic := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24
    return magic == 0x9BCFB9FC
}

func decryptCFB8(key, iv, ciphertext []byte) []byte {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil
    }
    
    out := make([]byte, len(ciphertext))
    reg := make([]byte, block.BlockSize())
    copy(reg, iv)
    buf := make([]byte, block.BlockSize())
    
    for i := 0; i < len(ciphertext); i++ {
        block.Encrypt(buf, reg)
        out[i] = ciphertext[i] ^ buf[0]
        copy(reg, reg[1:])
        reg[len(reg)-1] = ciphertext[i]
    }
    
    return out
}

func generateKeys(contentKey, baseUUID string) [][]byte {
    var keys [][]byte
    seen := make(map[string]bool)
    
    addKey := func(data []byte) {
        if len(data) == 0 {
            return
        }
        
        var key []byte
        if len(data) == 32 {
            key = data
        } else {
            hash := sha256.Sum256(data)
            key = hash[:]
        }
        
        keyStr := string(key)
        if !seen[keyStr] {
            seen[keyStr] = true
            keys = append(keys, key)
        }
    }
    
    // Basic variants
    addKey([]byte(contentKey))
    addKey([]byte(strings.ToUpper(contentKey)))
    addKey([]byte(strings.ToLower(contentKey)))
    
    // Combined with UUID
    addKey([]byte(contentKey + baseUUID))
    addKey([]byte(baseUUID + contentKey))
    
    // Hex decode attempts
    if decoded, err := hexDecode(contentKey); err == nil {
        addKey(decoded)
    }
    
    // Base64 decode attempts
    for _, variant := range []string{contentKey, contentKey + "=", contentKey + "=="} {
        if decoded, err := base64.StdEncoding.DecodeString(variant); err == nil {
            addKey(decoded)
        }
    }
    
    // Base32 decode attempts
    for _, variant := range []string{contentKey, contentKey + "=", contentKey + "=="} {
        if decoded, err := base32.StdEncoding.DecodeString(variant); err == nil {
            addKey(decoded)
        }
    }
    
    // PBKDF2 derivations
    if len(contentKey) >= 8 {
        for _, salt := range []string{"galaxite", "bedrock", baseUUID[:min(8, len(baseUUID))]} {
            if salt != "" {
                key := pbkdf2.Key([]byte(contentKey), []byte(salt), 1000, 32, sha256.New)
                addKey(key)
            }
        }
    }
    
    return keys
}

func hexDecode(s string) ([]byte, error) {
    if len(s)%2 != 0 {
        s = "0" + s
    }
    
    result := make([]byte, len(s)/2)
    for i := 0; i < len(s); i += 2 {
        var val byte
        for j := 0; j < 2; j++ {
            c := s[i+j]
            var nib byte
            switch {
            case c >= '0' && c <= '9':
                nib = c - '0'
            case c >= 'a' && c <= 'f':
                nib = c - 'a' + 10
            case c >= 'A' && c <= 'F':
                nib = c - 'A' + 10
            default:
                return nil, fmt.Errorf("invalid hex character")
            }
            val = (val << 4) | nib
        }
        result[i/2] = val
    }
    
    return result, nil
}

func normalizeLineEndings(data []byte) []byte {
    data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
    data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
    return bytes.TrimRight(data, "\x00")
}

func scanLocalZipEntries(data []byte) ([]string, map[string][]byte) {
    const lfhSig = 0x04034b50
    
    var names []string
    files := make(map[string][]byte)
    
    i := 0
    for i+30 < len(data) {
        sig := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
        if sig != lfhSig {
            i++
            continue
        }
        
        if i+30 > len(data) {
            break
        }
        
        method := int(data[i+8]) | int(data[i+9])<<8
        compSize := int(data[i+18]) | int(data[i+19])<<8 | int(data[i+20])<<16 | int(data[i+21])<<24
        nameLen := int(data[i+26]) | int(data[i+27])<<8
        extraLen := int(data[i+28]) | int(data[i+29])<<8
        
        hdrEnd := i + 30 + nameLen + extraLen
        if hdrEnd > len(data) {
            break
        }
        
        name := string(data[i+30 : i+30+nameLen])
        dataStart := hdrEnd
        dataEnd := dataStart + compSize
        
        if dataEnd > len(data) {
            dataEnd = len(data)
        }
        
        compData := data[dataStart:dataEnd]
        
        if method == 8 { // Deflate
            if r := flate.NewReader(bytes.NewReader(compData)); r != nil {
                if decompressed, err := io.ReadAll(r); err == nil {
                    files[name] = decompressed
                } else {
                    files[name] = compData
                }
                r.Close()
            } else {
                files[name] = compData
            }
        } else {
            files[name] = compData
        }
        
        names = append(names, name)
        i = dataEnd
    }
    
    return names, files
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
