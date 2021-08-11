//-s = matching strings
//-m = meta data
rule ruleC
{
  strings:
        $sampleIP = "10.0.1.7"
        $winSock = "Winsock" nocase
        $exactMatch = "Exact match"
    condition:
      any of them
      //$sampleIP or $winSock
      //$sampleIP and $winSock
}
