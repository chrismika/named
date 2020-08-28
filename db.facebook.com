$TTL 600
$ORIGIN facebook.com.

;
; SOA record
; ------------------------------X-------
@ IN SOA dns01.seenothing.net. public.seenothing.org. (
				2020051300 ; Serial Number (YYYYMMDDNN)
				3600 ; Refresh
				600 ; Retry
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

;
; A records
; ------------------------------X---------------X-----

;
; CNAME records
; ------------------------------X---------------X-----

;
; TXT records
; ------------------------------X---------------X-----
@				IN TXT		"This is a seenothing fake domain."
