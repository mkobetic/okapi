package libcrypto

var (

	// RSA 1024

	pemRSA1024 string = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDPpB/kTGjPmA5/gyNx7jT21/C+vh6AWUoIRU0QirB5WVqqsMHO
tzfWXPgyQySsl0uxkZ4gt4l0k65TnKMrvPliNQkfqLSL7o3w0Ag403axhdwzYji6
M5Xg0EaJTS81aFxA6bjF67I0nxmi/2jkm5OpnWNRThHYACT33NKo8IInZQIDAQAB
AoGAOswg88bnTxGh2V3LJbHscZHIbFrtzC58lkb5gZukSViSIg+Xce/T8fG1npYA
xpa5Knkvq9gNJmPDU43hbrs+apwcGI5T9SAV3eDqOn2jYPfFW7/rvbl1JH93Frnt
BFarG6TkrxnGp/123eW6HyFffZerafz7WakR5Pm3xQHfboECQQDx9HIJTcyw/47K
EO9ngNGSA0WU9OadYutH4u4ceItDFKVnxh/SSawNcgT7ATGVZq2zSKyEAgkIwaJ5
MSzqRyW1AkEA27HDBqkbRwFuJtnNWuJxlHeSxHiU+GeSgb7se0pmqrVod7UuIplQ
en7geKpl61m4alMfnGIZHsqgdvXluTII8QJBANs5VKnBaBlnNAU52vC48ymM9VrF
mr43hl6X6o65WdTpvASOqv5p6g40pPaYWki3w+KRkl35Sh448/FC8SNEW5ECQQDZ
mWgh4L0zxybjNDdCHaeB9i1YjFaA85UZDZINS9QEoUmnx7y6aEBeE+0hlyT7xxHx
vgNBUaiv5uKo8UVn+TcBAkBasoslV5vCnmM0nnfyY+l0tfM+FwDZowIRez4Sn6AW
XpAj/Pl/aQmpFUiUPN3bJGqw+hr4Im5Q1oxtk10msq8a
-----END RSA PRIVATE KEY-----`
	pemRSA1024Pub string = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPpB/kTGjPmA5/gyNx7jT21/C+
vh6AWUoIRU0QirB5WVqqsMHOtzfWXPgyQySsl0uxkZ4gt4l0k65TnKMrvPliNQkf
qLSL7o3w0Ag403axhdwzYji6M5Xg0EaJTS81aFxA6bjF67I0nxmi/2jkm5OpnWNR
ThHYACT33NKo8IInZQIDAQAB
-----END PUBLIC KEY-----`

	// DSA 1024

	pemDSA1024 string = `-----BEGIN DSA PRIVATE KEY-----
MIIBvAIBAAKBgQDHVxKXxWCHrPRcMH9om5eA+ZmpOUMJKId+EnxDNUh+I2TPKzcU
OhdgMRm5dNMkkqwzxUi7oQpQqXG0fW55l/HkgoTWz2A+K/Uf2MbX8adiR14vVzpN
UFhSYp72s8jdQjw6yug89nIOS7qwmEi9ytH78Fq7q7c6370VK0h987RULQIVAKZ2
Rjbzue6dRyIOOv+TZxhck1wpAoGAMd7CRqEujJqsAN/wtzLN7j4xJumoeFgdcvPQ
XrGSZHmwZUmf7VK2dt8I70tgTBVfxclyADjj7dXQaH9x8rjLRzRdBG5RAN5+ZcBk
V43bdaksTOCVkv/IzGhcpYKIu13UDDs1YJl+HOvGiPFAO0EteZVYegoYGVRHbchp
daEM29ECgYEArvgwlIF8OrnVoRV40GjWgBbAKhnh/KM9c7jqfN7rIpBWbgvXrFog
7S4UOPpXTt1ghTB9SS/CMTqqdb5AeFc2kI6ZSxNbDWrfKkNwytcwCGhwD1HnPt2S
sdVJhCcs9b6exlLElyqotgFrTKdjJbOL5cjOy9euxMJtXGBx+6d50e8CFQCY17tY
cQ+XS1zFlZEHZHvL7s4x7A==
-----END DSA PRIVATE KEY-----`
	pemDSA1024Pub string = `-----BEGIN PUBLIC KEY-----
MIIBtzCCASsGByqGSM44BAEwggEeAoGBAMdXEpfFYIes9Fwwf2ibl4D5mak5Qwko
h34SfEM1SH4jZM8rNxQ6F2AxGbl00ySSrDPFSLuhClCpcbR9bnmX8eSChNbPYD4r
9R/Yxtfxp2JHXi9XOk1QWFJinvazyN1CPDrK6Dz2cg5LurCYSL3K0fvwWrurtzrf
vRUrSH3ztFQtAhUApnZGNvO57p1HIg46/5NnGFyTXCkCgYAx3sJGoS6MmqwA3/C3
Ms3uPjEm6ah4WB1y89BesZJkebBlSZ/tUrZ23wjvS2BMFV/FyXIAOOPt1dBof3Hy
uMtHNF0EblEA3n5lwGRXjdt1qSxM4JWS/8jMaFylgoi7XdQMOzVgmX4c68aI8UA7
QS15lVh6ChgZVEdtyGl1oQzb0QOBhQACgYEArvgwlIF8OrnVoRV40GjWgBbAKhnh
/KM9c7jqfN7rIpBWbgvXrFog7S4UOPpXTt1ghTB9SS/CMTqqdb5AeFc2kI6ZSxNb
DWrfKkNwytcwCGhwD1HnPt2SsdVJhCcs9b6exlLElyqotgFrTKdjJbOL5cjOy9eu
xMJtXGBx+6d50e8=
-----END PUBLIC KEY-----`
	pemDSA1024Params string = `-----BEGIN DSA PARAMETERS-----
MIIBHgKBgQDHVxKXxWCHrPRcMH9om5eA+ZmpOUMJKId+EnxDNUh+I2TPKzcUOhdg
MRm5dNMkkqwzxUi7oQpQqXG0fW55l/HkgoTWz2A+K/Uf2MbX8adiR14vVzpNUFhS
Yp72s8jdQjw6yug89nIOS7qwmEi9ytH78Fq7q7c6370VK0h987RULQIVAKZ2Rjbz
ue6dRyIOOv+TZxhck1wpAoGAMd7CRqEujJqsAN/wtzLN7j4xJumoeFgdcvPQXrGS
ZHmwZUmf7VK2dt8I70tgTBVfxclyADjj7dXQaH9x8rjLRzRdBG5RAN5+ZcBkV43b
daksTOCVkv/IzGhcpYKIu13UDDs1YJl+HOvGiPFAO0EteZVYegoYGVRHbchpdaEM
29E=
-----END DSA PARAMETERS-----`

	// DH 1024

	pemDH1024Params string = `-----BEGIN DH PARAMETERS-----
MIGHAoGBAPm79VNHQBjWs4kF1gYI2bX3qOsIt3DBlLdxc6ZqKwFuamupaJkNdRF0
zxZONdJ6EHMbztFJjTEDZMY8Gl2aHQbu0/1+DmKKO2B2JoaYYdvbQxhDN/zP+Jvq
YA60mv1npYdnUfM2ji9uj6DwNPJIi8a8V0dHbwt/Ard8B7VyDB9TAgEC
-----END DH PARAMETERS-----`
)
