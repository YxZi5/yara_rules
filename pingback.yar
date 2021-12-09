rule pingback2
{
	meta:
		description = "Rule detection ping back or icmp c2 connections"
		author = "Yxzi"
		date = "07/11/2021"
		referecne = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel/"

	strings:
		$string1 = "shell"
		$string2 = "upload"
		$string3 = "upload2"
		$string4 = "exep"
		$string5 = "calc.exe"
		$string6 = "download"

		$hex_string = { 73 68 65 6c  }
		$hex_string2 = { 75 70 6c 6f 61 64 }
		
	condition:
		all of them
}