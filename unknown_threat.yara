rule SSH_detector {
        meta:
                Author = "@hsinwenchang"
                Description = "This rule detects the presence of SSH-One malware"
        strings:
                $path = "/tmp/SSH-One" nocase
                $port = "7758"
                
        condition:
                $path and $port

}