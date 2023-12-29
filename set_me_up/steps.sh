#!/bin/bash


function step_0() {
    echo "Step 0: Generate openssl.cnf"
    echo "Type a domain name (it does not need to be a real one):"
    read -r domain_name

    if [[ -f "openssl.cnf.example" ]]; then
        sed "s/<mydomain.com>/${domain_name}/g" openssl.cnf.example > openssl.cnf
        echo "openssl.cnf has been configured with the domain: $domain_name"
        echo $domain_name > step_0.out
    else
        echo "Error: openssl.cnf.example does not exist."
    fi
}

function step_1() {
    domain_name=`cat step_0.out`
    echo "Edit your /etc/hosts file to map your server ip to $domain_name"
    echo "PRESS ENTER to confirm you have done so"

    read -r 
    echo "done" > step_1.out
}

function step_2() {
    echo "Configure client.toml and server.toml from the provided examples in this directory."
    echo "The required certs (.pem) files are make targets."
    echo "(examine Makefile for openssl commands used)"
    echo "PRESS ENTER to confirm you have done so"

    read -r 
    echo "done" > step_2.out
}

printf "\n\n"

case "$1" in
    step_0)
        step_0
        ;;
    step_1)
        step_1
        ;;
    step_2)
        step_2
        ;;
    step_3)
        step_3
        ;;
    *)
        echo "No matching function found for the argument: $1"
        ;;
esac
