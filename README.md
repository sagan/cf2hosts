Mainly writen by Gemini 2.5 Pro

> Write a Go pogram using CloudFlare API, that when runned, fetch all A/CNAME/SRV DNS records of a domain or subdomain (e.g. "example.com"), then:
>
> 1. For A/CNAME records, update the "hosts" file of currrent OS, adding / updating the domain => ip pairs. Note the CNAME records should be resolved to ip, preferrably by using CloudFlare API directly. It should insert special comments as delimeter marks to the hosts file, only updating it's own managing part of the file.
> 2. If a optional `<save-srv-dir>` param is provided, for SRV records, like `_service._tcp.example.com`, saving records to files in the `<save-srv-dir>` using "service" as filename, the file should be in ipset ("hash:ip,port" type) save file format.
>
> The params of the program, like the CF API key, zone id, base domain, "save srv dir", could be provided by command line flags or environment variables. Also, provide a "dry-run" flag.

# Run

```
cf2hosts . -cf-token <token> -cf-zone <zone-id> -domain <example.com>
```
