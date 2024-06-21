*Continuation of computer security algorithms*
# Setup
There are three containers; Client, Flaskr, that are connected by a bridge network named `cns`
  * **Client**: a container with Firefox running on it. To access Firefox from host, connect via `http://localhost:5800`.
  * **Flaskr**: is hosting an HTTP server.

# How to run
1. Log into container repository,
   - `export CR_PAT=<your-personal-access-token>`
   - `echo $CR_PAT | podman login ghcr.io -u <your-github-username> --password-stdin`
   then run `podman-compose up -d` to build and start the containers.

2. Connect to Client's Firefox instance by visiting `http://localhost:5800` on host computer.

3. Access the HTTP server via `http://cns_flaskr` on the Client's Firefox instance.

4. Open three instances (3 terminals or tmux) of the Student container by running `podman exec -it cns_student /bin/bash` on each terminal.

5. Use the `dig` command to determine the IPs of Client and Flaskr containers.
    - `dig cns_client`
    - `dig cns_flaskr`

6. With this information, run arpspoof twice, once for each bash instance.
    - In the first bash window:
        - `arpspoof –t cns_client cns_flaskr`  (Tells cns_client that cns_flaskr is at cns_students MAC address)
    - In the second bash window:
        - `arpspoof –t cns_flaskr cns_client`  (Tells cns_flaskr that cns_client is at cns_students MAC address)
    - Reloading the page still shows the normal website, since Student is not yet blocking any packets.

7. Now run `bash add_iptables_rule.sh` to add a rule to `iptables` that forwards any packet with port 80 destination to the proxy.

8. You may verify that Client's browser will give an error when reloading the page. This is because Student is not blocking the packets but forwarding them to the proxy. Since the proxy is not active yet, the packets are simply dropped.

9. Activate the proxy in a transparent mode:
    - `mitmproxy -m transparent`

10. Reload the browser page; the honest page shows again, but mitmproxy shows that the request passed through Student.

11. Inspect traffics by clicking on each listing. Press key `q` to go back.

12. Shutdown the proxy and activate it again with a script.
    - `Ctrl + c → y → Enter`    (shutdown proxy)
    - `mitmproxy –m transparent –s proxy.py`

13. Reload the Firefox browser; title page changes to 'Flaskr-Spoofed' instead of 'Flaskr'.
