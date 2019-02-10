$TTL 600
$ORIGIN seenothing.org.

;
; SOA record
; ------------------------------X-------
@ IN SOA dns01.seenothing.net. public.seenothing.org. (
				<DATE>00 ; Serial Number (YYYYMMDDNN)
				3600 ; Refresh
				2419200 ; Expire
				600 ) ; Minimum

;
; NS records
; ------------------------------X---------------X-----
@				IN NS		dns01.seenothing.net.
@				IN NS		dns02.seenothing.net.
@				IN NS		dns03.seenothing.net.

;
; MX records
; ------------------------------X---------------X-----
@				IN MX		10 ASPMX.L.GOOGLE.COM.
@				IN MX		20 ALT1.ASPMX.L.GOOGLE.COM.
@				IN MX		20 ALT2.ASPMX.L.GOOGLE.COM.
@				IN MX		30 ASPMX2.GOOGLEMAIL.COM.
@				IN MX		30 ASPMX3.GOOGLEMAIL.COM.
public				IN MX		10 s101.seenothing.net.

;
; A records
; ------------------------------X---------------X-----
@				IN A		69.125.235.157

;
; CNAME records
; ------------------------------X---------------X-----
www				IN CNAME	ip.nj.seenothing.net.

;
; TXT records
; ------------------------------X---------------X-----
@				IN TXT		"v=spf1 a include:_spf.google.com ~all"
google._domainkey		IN TXT		"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiB2bkey+r8X3PTdlMey9poi2SHXMWrBtixWRPmVylTxjfQo4xNIV5dFpEvMGs7eDmWSgcjoA9L1iiQh7k8uKg/bwVcBpD2iPHEfU5Ll4Rmg4c91vv2qKG15U/gb9siyB1eHUdWUJQaP/UhV3ElXbfC7k4VehR8ro0EM9tWP52Ox2169xttg/iLdwnIIChZnr" "ewGfpRU17E20k7hG2P+gMyPNZiOmRprgSIIWshm9injPMlfAXKtLs+XDhuvr4JbUjTOcZwPzF030xYE69hZWedCMjpEDDCzn1Q0FHLOLIgR+IpEfgXgH8gFXwxz8wz0cWWPO/jEG0u8NvrHq6+zjXQIDAQAB"
public				IN TXT		"v=spf1 a include:_spf.google.com ~all"
