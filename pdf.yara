//-s = matching strings
//-m = meta data
/*
I began dissecting PDF'S for malware.
I started to experiment with tools from Backtrack(older version of Kali) I realized why not write a Yara rule to automate the process.
To view a raw pdf you can use any text editor generally speaking and maybe Ghidra(it imports as a raw binary/unrecognized file format) 
It would be easier in my opinion to view the bytes instead of the raw bytes.

There are a few strings that will generate false flags.
http & https will generate false flags on a good pdf.
On a malicious pdf the urls may be the C2 server. "let" will hopefully be in an abyss of data & not the JS keyword.

**If you're reading a cyber security report some of these strings will get flagged!

**OpenAction is common on PDFS. I downloaded various cyber reports and most are tailored to Adobe(created with Adobe) hint openaction.
**I recommend disabling JavaScript in your PDF viewer whether that be a Browser or Adobe
yara -m -s pdf.yara cyberReport.pdf
*/

rule pdf
{
  strings:
        $sampleIP = "/JS" nocase
        $test = "openaction" //Counted as string?
        $terminal0 = "powershell.exe"
        $terminal1 = "cmd.exe"
        $action = "/OpenAction" nocase //Adobe PDF'S have this flag
        $launch = "/Launch"
        //The javascript keywords will most likely give a false flag.
        $varNames0 = "var" //Javascript keyword
        $varNames1 = "let" //Javascript keyword
        $command0 = "bash"
        $command1 = "ftp"
        $JSF0 = "download" //Download a file in Javascript
        $JSF1 = "<a>"
        $crypt0 = "xor"
        $crypt1 = "crypt"
        $proto0 = "http://" //May generate a false positive depending on the PDF
        $proto1 = "tcp" nocase
        $proto2 = "https://"
        $port0 = "4444"
    condition:
      any of them
}
