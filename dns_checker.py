import socket


def check_dns(domain):

    try:

        results = socket.getaddrinfo(
            domain,
            None,
            type=socket.SOCK_STREAM
        )

        addresses = sorted(
            set(item[4][0] for item in results)
        )

        return {

            "status": "DNS resolution successful",

            "addresses": addresses

        }

    except socket.gaierror:

        return {

            "status": "DNS resolution failed",

            "addresses": []

        }