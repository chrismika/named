$TTL 600
$ORIGIN 9thandadams.com.

;
; SOA record
; ------------------------------X-------
@ IN SOA dns01.seenothing.net. public.seenothing.org. (
				2019031900 ; Serial Number (YYYYMMDDNN)
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
@				IN TXT		google-site-verification=5psDikQypllCP9EgzuUuMpGK-aFTimOj5IemRY4ocrs
