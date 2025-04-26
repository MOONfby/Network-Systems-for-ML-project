import topology


def ping(client, server, expected, count=1, wait=1):

    # TODO: What if ping fails? How long does it take? Add a timeout to the command!
    cmd = f"ping -c {count} -W {wait} {server} >/dev/null 2>&1; echo $?"
    ret = client.cmd(cmd    ret = int(client.cmd(cmd).strip()))
    # TODO: Here you should compare the return value "ret" with the expected value
    # (consider both failures
    return (ret == 0) == expected # True means "everyhing went as expected"


def curl(client, server, method="GET", payload="", port=80, expected=True):
        """
        run curl for HTTP request. Request method and payload should be specified
        Server can either be a host or a string
        return True in case of success, False if not
        """

        if (isinstance(server, str) == 0):
            server_ip = str(server.IP())
        else:
            # If it's a string it should be the IP address of the node (e.g., the load balancer)
            server_ip = server

        # TODO: Specify HTTP method
        # TODO: Pass some payload (a.k.a. data). You may have to add some escaped quotes!
        # The magic string at the end reditect everything to the black hole and just print the return code
        curl_cmd = f"curl -X {method} -s -o /dev/null -w '%{{http_code}}'"
        if payload:
            curl_cmd += f" -d '{payload}'"
        cmd = f"{curl_cmd} http://{server}:{port}"
        ret = client.cmd(cmd).strip()
        
        # TODO: What value do you expect?
        return (ret in ["200", "403"]) == expected  # True means "everyhing went as expected"
