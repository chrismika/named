$TTL 600
$ORIGIN 9thandadams.com.

;
; SOA record
; ------------------------------X-------
@ IN SOA dns01.seenothing.net. public.seenothing.org. (
				2019031901 ; Serial Number (YYYYMMDDNN)
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
@				IN MX		1 aspmx.l.google.com.
@				IN MX		5 alt1.aspmx.l.google.com.
@				IN MX		5 alt2.aspmx.l.google.com.
@				IN MX		10 aspmx2.googlemail.com.
@				IN MX		10 aspmx3.googlemail.com.

;
; A records
; ------------------------------X---------------X-----

;
; CNAME records
; ------------------------------X---------------X-----

;
; TXT records
; ------------------------------X---------------X-----
