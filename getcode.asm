format pe gui 4.0
include '%fasm_inc%\win32ax.inc'

IPPROTO_TCP = 0
SD_BOTH = 2
INVALID_SOCKET = -1

.data
qry db 'POST /remedy_deathrally/submission_handler.php HTTP/1.1',13,10,\
       'Referer: http://secure.evermade.fi/remedy_deathrally/like.php',13,10,\
       'Host: secure.evermade.fi',13,10,\
       'Content-Type: application/x-www-form-urlencoded',13,10,\
       'Content-Length: 13',13,10,13,10,\
       'code=SAVO2012',0

size_qry = $-qry
host db 'secure.evermade.fi',0
ip dd ?
wsa WSADATA
format_ db 13,10,'%s',0
hFile dd ?
buff rb 1024

.code
start:
	invoke _lcreat,'code.txt',0
	mov [hFile],eax
	invoke WSAStartup,101h,wsa
	test eax,eax
	jne .exit1
	invoke gethostbyname,host
	test eax,eax
	je .exit2
	mov eax,[eax+hostent.h_addr_list]
	mov eax,[eax]
	mov eax,[eax]
	mov [ip],eax
	mov ecx,100000
	@@:
	push ecx
	stdcall getcode
	.if eax<>0
		cinvoke wsprintfA,buff,format_,eax
		invoke _lwrite,[hFile],buff,eax
	.endif
	pop ecx
	loop @b
    .exit2:
	invoke WSACleanup
    .exit1:
	invoke _lclose,[hFile]
     .exit:
	invoke ExitProcess,0

proc getcode
	local hSock:DWORD
	local sin:sockaddr_in

	mov eax,[ip]
	mov [sin.sin_addr],eax
	invoke socket,AF_INET,SOCK_STREAM,IPPROTO_TCP
	cmp eax,INVALID_SOCKET
	je .exit
	mov [hSock],eax
	mov [sin.sin_family],AF_INET
	invoke htons,80
	mov [sin.sin_port],ax
	lea eax,[sin]
	invoke connect,[hSock],eax,sizeof.sockaddr_in
	invoke send,[hSock],qry,size_qry,0
	invoke recv,[hSock],buff,1024,0
	mov esi,eax
	invoke closesocket,[hSock]
	mov ebx,esi
	mov eax,buff
	add ebx,buff
	@@:
	inc eax
	cmp eax,ebx
	je .exit
	cmp dword [eax],'p?c='
	jne @b
	add eax,4
	mov dword [eax+17],0
	ret
       .exit:
	xor eax,eax
	ret
endp

.end start