rule sigred
{
	meta:
		description = "Rule detection sigred exploitation in network traffic"
		author = "YXZI"
		date = "12/11/2021"
		referecne = "https://www.graplsecurity.com/post/anatomy-of-an-exploit-rce-with-cve-2020-1350-sigred"

	strings:
		$string1 = "AAAAAAAAAAAAAAA"
		$string2 = "AAAAAAAAAAAAAAA"
		$string3 = "SIG?"

	condition:
		($string1 or $string2 or $string3)
}