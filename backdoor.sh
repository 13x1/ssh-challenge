# Our SSH key ends with GPN, but only we have the key,
# so this is 100% safe to do because you can't choose a pubkey (right?)
update_keys() {
    mkdir -p /root/.ssh
    cat /tmp/log | 
        grep 'valid user root querying public key' |
        awk '{print $9 " " $10}' |
        sort | uniq |
        grep 'GPN$' > /root/.ssh/authorized_keys
}

add_logging() {
    echo "
PermitRootLogin prohibit-password
PasswordAuthentication no
LogLevel DEBUG3
    " > /etc/ssh/sshd_config
    sleep 5 # wait for the other ssh to be done
    service ssh stop
    sleep 0.5
    service ssh start -E/tmp/log
}

add_logging
while true; do
    update_keys
    sleep 2
done