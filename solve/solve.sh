remote() {
    ssh -i id_ed25519 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 2222 root@localhost $@
}

if [ ! -f id_ed25519 ]; then
    echo generating key
    cargo run --release
    chmod 600 id_ed25519
fi
echo generating public key
ssh-keygen -y -f id_ed25519 > id_ed25519.pub
echo pushing key to server
remote echo you already solved it lol 2>/dev/null
echo waiting for key to be scanned
sleep 3
echo extracting flag
remote id 2>/dev/null
echo -n FLAG:; remote cat /flag.txt 2>/dev/null; echo; echo;
remote 2>/dev/null